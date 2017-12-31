# Reflector
Project done as part of security course which is used to reflect attacks done at at network level

## Requirements
- Libnet 1.1.4
- Libpcap 1.7.4

## Compilation
<pre> gcc -Wall reflector.c -o reflector -lpcap -lnet </pre>

## Execution
<pre>./reflector --victim-ip [IP Addr] --victim-ethernet [Ethernet Addr] --relayer-ip [IP Addr] --relayer-ethernet [Ethernet Addr] </pre>

For example, <br>
<pre>./reflector --victim-ip 192.168.1.11 --victim-ethernet 00:0A:0B:0C:11:37 --relayer-ip 192.168.1.9 --relayer-ethernet 00:0A:06:1B:AB:B0 </pre>
