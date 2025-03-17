#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include "checksum.h"

#define SOURCE_PORT 5050
#define SOURCE_ADDRESS "192.0.2.1"

struct pseudo_header {
    struct in_addr ip_src, ip_dst;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short length;
};

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <TARGET IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }

    unsigned char packet[sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct pseudo_header)] = {0};
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header *pseudo_header = (struct pseudo_header *)(packet + sizeof(struct ip) + sizeof(struct tcphdr));

    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_header->ip_id = htons(rand() % 65535);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_src.s_addr = inet_addr(SOURCE_ADDRESS);
    ip_header->ip_dst.s_addr = inet_addr(argv[1]);

    tcp_header->th_sport = htons(SOURCE_PORT);
    tcp_header->th_dport = htons(atoi(argv[2]));
    tcp_header->th_seq = htonl(rand() % 4294967295);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(65535);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    pseudo_header->ip_src.s_addr = ip_header->ip_src.s_addr;
    pseudo_header->ip_dst.s_addr = ip_header->ip_dst.s_addr;
    pseudo_header->reserved = 0;
    pseudo_header->protocol = ip_header->ip_p;
    pseudo_header->length = htons(sizeof(struct tcphdr));

    tcp_header->th_sum = internet_checksum((unsigned short *)tcp_header, sizeof(struct tcphdr) + sizeof(struct pseudo_header));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(atoi(argv[2]));
    target.sin_addr.s_addr = ip_header->ip_dst.s_addr;

    printf("Sending SYN packets...\n");
    print_hex(packet, ntohs(ip_header->ip_len));

    while (1) {
        if (sendto(sockfd, packet, ntohs(ip_header->ip_len), 0, (struct sockaddr *)&target, sizeof(target)) == -1) {
            perror("sendto()");
        }
        sleep(1);
    }

    close(sockfd);
    return 0;
}
