/* Mohith Pukale, mohithpukale@cs.ucsb.edu */

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <libnet.h>

// Debug flag used while checking the code
#define DEBUG 0

// Fixed variables
#define IP_ADDR_LEN 4
#define ETHERNET_SIZE 14
#define UDP_SIZE 8
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

// Referenced from http://www.tcpdump.org/pcap.html
/* Ethernet header */
struct sniff_ethernet {
    u_int8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_int8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_int16_t ether_type; /* IP? ARP? RARP? etc */
#define ETHER_IP 0x0008
#define ETHER_ARP 0x0608
};

/* ARP Header */
struct sniff_arp {
    u_short arp_ht;                     /* hardware type */
    u_short arp_pt;                     /* protocol type */
    u_char arp_hlen;                    /* hardware address length */
    u_char arp_plen;                    /* protocol address length */
    u_short arp_op;                     /* operation */
    u_char arp_sha[ETHER_ADDR_LEN];     /* sender hardware address */
    u_char arp_spa[IP_ADDR_LEN];        /* sender protocol address */
    //struct in_addr arp_spa;           /* bugged */
    u_char arp_tha[ETHER_ADDR_LEN];     /* target hardware address */
    u_char arp_tpa[IP_ADDR_LEN];        /* target protocol address */
    //struct in_addr arp_tpa;           /* bugged */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;    /* version << 4 | header length >> 2 */
    u_char ip_tos;    /* type of service */
    u_short ip_len;   /* total length */
    u_short ip_id;    /* identification */
    u_short ip_off;   /* fragment offset field */
#define IP_RF 0x8000    /* reserved fragment flag */
#define IP_DF 0x4000    /* dont fragment flag */
#define IP_MF 0x2000    /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl;    /* time to live */
    u_char ip_p;    /* protocol */
    u_short ip_sum;   /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)    (((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
    u_int16_t th_sport; /* source port */
    u_int16_t th_dport; /* destination port */
    u_int32_t th_seq;   /* sequence number */
    u_int32_t th_ack;   /* acknowledgement number */

    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_int8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_int16_t th_win;   /* window */
    u_int16_t th_sum;   /* checksum */
    u_int16_t th_urp;   /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_int16_t uh_dport;
    u_int16_t uh_sport;
    u_int16_t uh_length;
    u_int16_t uh_sum;
};

void print_mac_address(u_int8_t *macaddr);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void spoof_arp(in_addr_t ipaddr, in_addr_t destip, u_int8_t *macaddr, u_int8_t *destmacaddr);

u_int32_t get_payload_size(u_int8_t *payload);

char *dev;                      /* The device to sniff on */
char *victim_ip;
char *victim_ethernet;
char *relayer_ip;
char *relayer_ethernet;

int main(int argc, char *argv[]) {
    pcap_t *handle;                 /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;          /* The compiled filter */
    char filter_exp[255] = "";      /* The filter expression */
    bpf_u_int32 mask;               /* Host netmask */
    bpf_u_int32 net;                /* Host IP */


    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--interface") == 0) {
            dev = argv[i + 1];
            i = i + 1;
        } else if (strcmp(argv[i], "--victim-ip") == 0) {
            victim_ip = argv[i + 1];
            i = i + 1;
        } else if (strcmp(argv[i], "--victim-ethernet") == 0) {
            victim_ethernet = argv[i + 1];
            i = i + 1;

        } else if (strcmp(argv[i], "--relayer-ip") == 0) {
            relayer_ip = argv[i + 1];
            i = i + 1;
        } else if (strcmp(argv[i], "--relayer-ethernet") == 0) {
            relayer_ethernet = argv[i + 1];
            i = i + 1;
        } else {
            printf("%s\n", argv[i - 1]);
            printf("Invalid commandline parameter: %s\n", argv[i]);
            return 1;
        }
    }

    if (victim_ethernet == NULL || relayer_ethernet == NULL) {
        fprintf(stderr, "You have to specify both victim and relayer ethernet address\n");
        exit(1);
    }

    if (victim_ip == NULL || relayer_ip == NULL) {
        fprintf(stderr, "You have to specify both victim and relayer IP address\n");
        exit(1);
    }


    // Initialization stage

    printf("    Initializing Reflector\n");

    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
    }

    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(1);
    }

    // Generate filter: dst (relayer or victim) to sniff packets to be relayed later
    strcat(filter_exp, "dst (");
    strcat(filter_exp, relayer_ip);
    strcat(filter_exp, " or ");
    strcat(filter_exp, victim_ip);
    strcat(filter_exp, ")");

    printf("    Filter Added: %s\n", filter_exp);

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }


    // Listening stage
    printf("    Started listening for packets\n");
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return (0);

}


// Callback handler
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp;
    u_int8_t *payload; /* Packet payload */

    u_int size_ip;
    u_int size_protocol;
    u_int16_t length_protocol;

    /* Spoofed src and the real dst of the packets */
    u_int32_t dip;
    u_int32_t sip;
    u_int8_t *daddr;
    u_int8_t *saddr;


    if (packet == NULL) {
        printf("  - No packet received\n");
        return;
    }

    if (DEBUG == 1) {
        printf(" DEBUG: Packet is not null\n Packet Type:\n");
    }

    ethernet = (struct sniff_ethernet *) (packet);

    if (ethernet->ether_type == ETHER_IP) {
        ip = (struct sniff_ip *) (packet + ETHERNET_SIZE);
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            printf("   - Invalid IP header length: %i bytes\n", size_ip);
            return;
        }

        if (DEBUG == 1) {
            printf("  - It's a valid IP packet\n");
        }

        /* Distinguish between TCP and UDP packets */
        if (ip->ip_p == TCP_PROTOCOL) {
            tcp = (struct sniff_tcp *) (packet + ETHERNET_SIZE + size_ip);
            size_protocol = TH_OFF(tcp) * 4;
            if (size_protocol < 20) {
                printf("   - Invalid TCP header length: %u bytes\n", size_protocol);
                return;
            }

        } else if (ip->ip_p == UDP_PROTOCOL) {
            udp = (struct sniff_udp *) (packet + ETHERNET_SIZE + size_ip);
            size_protocol = UDP_SIZE;
        }
    } else if (ethernet->ether_type == ETHER_ARP) {
        struct sniff_arp *arp;
        arp = (struct sniff_arp *) (packet + ETHERNET_SIZE);

        if (DEBUG) {
            printf("  - It's a ARP Packet\n");
        }

        int length;
        spoof_arp(inet_addr(victim_ip),         /* target protocol address */
                  inet_addr((char *) arp->arp_spa),         /* destination protocol address */
                  (u_int8_t *) libnet_hex_aton(victim_ethernet, &length),         /* target hw address */
                  (u_int8_t *) &arp->arp_sha);         /* destination protocol address */

        spoof_arp(inet_addr(relayer_ip),
                  inet_addr((char *) arp->arp_spa),
                  (u_int8_t *) libnet_hex_aton(relayer_ethernet, &length),
                  (u_int8_t *) &arp->arp_sha);

        return;
    } else {
        fprintf(stderr, "Don't know this protocol. Shutting down\n");
        exit(1);
    }



    // Figuring out the source and destination for attacker

    if (DEBUG == 1) {
        printf(" DEBUG: Deciding source and destination addresses:\n");
    }


    int length;

    if (ip->ip_dst.s_addr == inet_addr(victim_ip)) {
        sip = inet_addr(relayer_ip);
        saddr = (u_int8_t *) libnet_hex_aton(relayer_ethernet, &length);
        if (saddr == NULL) {
            fprintf(stderr, "Couldn't Convert MAC address: %s\n", relayer_ethernet);
            exit(1);
        }

        if (DEBUG == 1) {
            printf("  - Src IP:     %s\n", relayer_ip);
            printf("  - Dst Ether:  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                   saddr[0], saddr[1], saddr[2], saddr[3], saddr[4], saddr[5]);
        }
    } else if (ip->ip_dst.s_addr == inet_addr(relayer_ip)) {
        sip = inet_addr(victim_ip);
        saddr = (u_int8_t *) libnet_hex_aton(victim_ethernet, &length);
        if (saddr == NULL) {
            fprintf(stderr, "Couldn't Convert MAC address: %s\n", victim_ethernet);
            exit(1);
        }

        if (DEBUG == 1) {
            printf("  - Src IP:     %s\n", victim_ip);
            printf("  - Dst Ether:  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                   saddr[0], saddr[1], saddr[2], saddr[3], saddr[4], saddr[5]);
        }
    }


    dip = ip->ip_src.s_addr;
    daddr = (u_int8_t *) ethernet->ether_shost;

    if (daddr == NULL) {
        fprintf(stderr, "Couldn't fetch the dst MAC address from ethernet header\n");
        exit(1);
    }


    if (DEBUG == 1) {
        printf("  - Dst IP:     %s\n", inet_ntoa(ip->ip_src));
        printf("  - Dst Ether:  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               daddr[0], daddr[1], daddr[2], daddr[3], daddr[4], daddr[5]);
    }

    // Generating packet
    if (DEBUG == 1) {
        printf(" DEBUG: Trying to generate packet\n");
    }

    libnet_t *l;
    char errbuf_net[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_LINK, dev, errbuf_net);
    if (l == NULL) {
        fprintf(stderr, "Error Opening Context: %s\n", errbuf_net);
        return;
    }

    if (ethernet->ether_type == ETHER_IP) {

        if (ip->ip_p == TCP_PROTOCOL) {

            libnet_ptag_t libnet_tcp = 0;
            int size_payload;
            size_payload = ntohs(ip->ip_len) - (size_ip + size_protocol);

            u_int8_t *tcp_options = (u_int8_t *) (packet + ETHERNET_SIZE + size_ip + 20);
            u_int32_t size_tcp_options = (u_int32_t) (size_protocol - 20);
            libnet_build_tcp_options(tcp_options, size_tcp_options, l, 0);

            if (size_payload == 0) {
                payload = NULL;
            } else {
                payload = (u_int8_t *) (packet + ETHERNET_SIZE + size_ip + size_protocol);
            }

            if (DEBUG == 1) {
                printf("  - Size of payload %i\n", size_payload);
                printf("  - Size of IP header %i\n", size_ip);
                printf("  - Size of IP length %i\n", ip->ip_len);
            }

            length_protocol = size_protocol + size_payload;

            libnet_tcp = libnet_build_tcp(htons(tcp->th_sport),
                                          htons(tcp->th_dport),
                                          ntohl(tcp->th_seq),
                                          ntohl(tcp->th_ack),
                                          tcp->th_flags,
                                          ntohs(tcp->th_win),
                                          0,
                                          ntohs(tcp->th_urp),
                                          length_protocol,
                                          payload,
                                          size_payload,
                                          l,
                                          libnet_tcp);


            if (libnet_tcp == -1) {
                fprintf(stderr, "Unable to build TCP header: %s\n", libnet_geterror(l));
                exit(1);
            }

            if (DEBUG == 1) {
                printf("  - IP packet successfully generated\n");
            }

        } else if (ip->ip_p == UDP_PROTOCOL) {


            libnet_ptag_t libnet_udp = 0;
            int size_payload;
            size_payload = ntohs(ip->ip_len) - size_ip;
            payload = (u_int8_t *) (packet + ETHERNET_SIZE + size_ip + size_protocol);
            length_protocol = (udp->uh_length) + size_payload;

            libnet_udp = libnet_build_udp(htons(udp->uh_sport),
                                          htons(udp->uh_dport),
                                          length_protocol,
                                          0,
                                          payload,
                                          size_payload,
                                          l,
                                          libnet_udp);

            if (libnet_udp == -1) {
                fprintf(stderr, "Unable to build UDP header: %s\n", libnet_geterror(l));
                exit(1);
            }
        }

        // Create a new IP packet
        u_int8_t *ip_options = (u_int8_t *) (packet + ETHERNET_SIZE + 20);
        u_int32_t size_ip_options = (u_int32_t) (size_ip - 20);
        libnet_build_ipv4_options(ip_options, size_ip_options, l, 0);

        int size_ip_payload;
        u_int8_t *ip_payload;

        if (ip->ip_p == TCP_PROTOCOL || ip->ip_p == UDP_PROTOCOL) {
            ip_payload = NULL;
            size_ip_payload = 0;
        } else {
            ip_payload = (u_int8_t *) (packet + ETHERNET_SIZE + size_ip);
            size_ip_payload = ntohs(ip->ip_len) - size_ip;
        }

        libnet_ptag_t libnet_ipv4 = 0;
        libnet_ipv4 = libnet_build_ipv4(ntohs(ip->ip_len),
                                        ip->ip_tos,
                                        ntohs(ip->ip_id),
                                        ntohs(ip->ip_off),
                                        ip->ip_ttl,
                                        ip->ip_p,
                                        0,
                                        sip,
                                        dip,
                                        ip_payload,
                                        size_ip_payload,
                                        l,
                                        libnet_ipv4);

        if (libnet_ipv4 == -1) {
            fprintf(stderr, "Unable to build IPv4 header: %s\n", libnet_geterror(l));
            exit(1);
        }
    }

    libnet_ptag_t libnet_eth = 0;
    libnet_eth = libnet_build_ethernet(daddr,
                                       saddr,
                                       ETHERTYPE_IP,
                                       NULL,
                                       0,
                                       l,
                                       libnet_eth);

    if (libnet_eth == -1) {
        fprintf(stderr, "Unable to build Ethernet header: %s\n", libnet_geterror(l));
        exit(1);
    }

    if (DEBUG == 1) {
        printf("  - Ethernet packet successfully generated\n");
    }

    if ((libnet_write(l)) == -1) {
        fprintf(stderr, "Unable to send packet: %s\\n", libnet_geterror(l));
        exit(1);
    } else {
        if (DEBUG == 1) {
            printf("  - IP packet replicated and sent\n");
        }

    }


    libnet_destroy(l);

}

// Spoofing ARP packets
void spoof_arp(in_addr_t ipaddr, in_addr_t destip, u_int8_t *macaddr, u_int8_t *destmacaddr) {
    libnet_ptag_t arp = 0;                /* ARP protocol tag */
    libnet_ptag_t eth = 0;                /* Ethernet protocol tag */

    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_LINK, dev, errbuf);

    if (l == NULL) {
        fprintf(stderr, "Error Opening Context: %s\n", errbuf);
        exit(1);
    }

    arp = libnet_autobuild_arp(ARPOP_REPLY,
                               macaddr,
                               (u_int8_t *) &ipaddr,
                               destmacaddr,
                               (u_int8_t *) &destip,
                               l);

    if (arp == -1) {
        fprintf(stderr,
                "Unable to build ARP header: %s\n", libnet_geterror(l));
        exit(1);
    }

    eth = libnet_build_ethernet(destmacaddr,
                                macaddr,
                                ETHERTYPE_ARP,
                                NULL,
                                0,
                                l,
                                eth);

    if (eth == -1) {
        fprintf(stderr,
                "Unable to build Ethernet header: %s\n", libnet_geterror(l));
        exit(1);
    }

    if ((libnet_write(l)) == -1) {
        fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
        exit(1);
    } else {
        if (DEBUG == 1) {
            printf("  - ARP packet replicated and sent\n");
        }
    }

    libnet_destroy(l);


}