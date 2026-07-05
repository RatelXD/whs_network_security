# WHS Network Security - PCAP Programming

C 기반 PCAP API를 활용하여 TCP 패킷의 Ethernet, IP, TCP, HTTP 정보를 출력하는 과제 코드입니다.

## Build

```bash
gcc -Wall -Wextra -o pcap_http_sniffer pcap_programming/pcap_http_sniffer.c -lpcap
