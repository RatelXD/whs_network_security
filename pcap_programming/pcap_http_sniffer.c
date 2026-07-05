#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ETHER_TYPE_IP 0x0800
#define IPPROTO_TCP_NUM 6
#define MAX_HTTP_PRINT 1000

// Ethernet 헤더 구조
struct ethheader {
    u_char ether_dhost[6];   // 목적지 MAC
    u_char ether_shost[6];   // 출발지 MAC
    u_short ether_type;      // 상위 프로토콜 타입
};

// IP 헤더 구조
struct ipheader {
    unsigned char iph_ihl:4;      // IP 헤더 길이
    unsigned char iph_ver:4;      // IP 버전
    unsigned char iph_tos;
    unsigned short int iph_len;   // IP 패킷 전체 길이
    unsigned short int iph_ident;
    unsigned short int iph_flag:3;
    unsigned short int iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;   // TCP/UDP/ICMP 구분
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;  // 출발지 IP
    struct in_addr iph_destip;    // 목적지 IP
};

// TCP 헤더 구조
struct tcpheader {
    unsigned short int tcp_sport;       // 출발지 포트
    unsigned short int tcp_dport;       // 목적지 포트
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char tcp_reserved:4;
    unsigned char tcp_offset:4;         // TCP 헤더 길이
    unsigned char tcp_flags;
    unsigned short int tcp_window;
    unsigned short int tcp_checksum;
    unsigned short int tcp_urgentptr;
};

// MAC 주소 출력
void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// HTTP 메시지인지 간단히 확인
int is_http_message(const u_char *data, int len) {
    if (len <= 0) return 0;

    return !strncmp((char *)data, "GET ", 4) ||
           !strncmp((char *)data, "POST ", 5) ||
           !strncmp((char *)data, "HEAD ", 5) ||
           !strncmp((char *)data, "PUT ", 4) ||
           !strncmp((char *)data, "DELETE ", 7) ||
           !strncmp((char *)data, "OPTIONS ", 8) ||
           !strncmp((char *)data, "HTTP/", 5);
}

// HTTP payload 출력
void print_http_payload(const u_char *data, int len) {
    int print_len = len;

    if (print_len > MAX_HTTP_PRINT) {
        print_len = MAX_HTTP_PRINT;
    }

    for (int i = 0; i < print_len; i++) {
        if (data[i] == '\r') continue;

        if (data[i] == '\n') {
            putchar('\n');
        } else if (isprint(data[i]) || data[i] == '\t') {
            putchar(data[i]);
        } else {
            putchar('.');
        }
    }

    putchar('\n');
}

// 캡처된 패킷 처리
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;

    // Ethernet 헤더 추출
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != ETHER_TYPE_IP) {
        return;
    }

    // IP 헤더 추출
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol != IPPROTO_TCP_NUM) {
        return;
    }

    // IP 헤더 길이를 이용해 TCP 헤더 위치 계산
    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // TCP 헤더 길이를 이용해 payload 위치 계산
    int tcp_header_len = tcp->tcp_offset * 4;
    int ip_total_len = ntohs(ip->iph_len);
    int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    if (payload_len < 0 || header->caplen < (unsigned int)payload_offset) {
        return;
    }

    const u_char *payload = packet + payload_offset;

    printf("\n================ TCP Packet ================\n");

    printf("[Ethernet Header]\n");
    printf("Source MAC      : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Destination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("\n[IP Header]\n");
    printf("Source IP       : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("IP Header Len   : %d bytes\n", ip_header_len);

    printf("\n[TCP Header]\n");
    printf("Source Port     : %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
    printf("TCP Header Len  : %d bytes\n", tcp_header_len);

    if (payload_len > 0 && is_http_message(payload, payload_len)) {
        printf("\n[HTTP Message]\n");
        print_http_payload(payload, payload_len);
    }

    printf("============================================\n");
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char *dev = "ens33";
    char *filter_exp = "tcp";

    if (argc >= 2) {
        dev = argv[1];
    }

    if (argc >= 3) {
        filter_exp = argv[2];
    }

    // 네트워크 인터페이스에서 패킷 캡처 시작
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return 1;
    }

    // TCP 패킷만 캡처하도록 BPF 필터 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("[*] Device : %s\n", dev);
    printf("[*] Filter : %s\n", filter_exp);
    printf("[*] Packet capture started. Press Ctrl+C to stop.\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
