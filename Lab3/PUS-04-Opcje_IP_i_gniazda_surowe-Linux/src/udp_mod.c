#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <error.h>
#include "checksum.h"

#define SOURCE_PORT 5050
#define SOURCE_ADDRESS "192.0.2.1"

struct phdr {
    struct in_addr ip_src, ip_dst;
    unsigned char unused;
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
    int sockfd, socket_option = 1, retval;
    struct addrinfo hints, *rp, *result;
    unsigned short checksum;
    unsigned char datagram[sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct phdr)] = {0};
    struct ip *ip_header = (struct ip *)datagram;
    struct udphdr *udp_header = (struct udphdr *)(datagram + sizeof(struct ip));
    struct phdr *pseudo_header = (struct phdr *)(datagram + sizeof(struct ip) + sizeof(struct udphdr));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <HOSTNAME OR IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_UDP;

    retval = getaddrinfo(argv[1], NULL, &hints, &result);
    if (retval != 0) {
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(retval));
        exit(EXIT_FAILURE);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            perror("socket()");
            continue;
        }

        retval = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &socket_option, sizeof(int));
        if (retval == -1) {
            perror("setsockopt()");
            exit(EXIT_FAILURE);
        }
        break;
    }
    if (rp == NULL) {
        fprintf(stderr, "Failed to create socket.\n");
        exit(EXIT_FAILURE);
    }

    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = sizeof(struct ip) + sizeof(struct udphdr);
    ip_header->ip_id = 0;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_src.s_addr = inet_addr(SOURCE_ADDRESS);
    ip_header->ip_dst.s_addr = ((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr;

    udp_header->uh_sport = htons(SOURCE_PORT);
    udp_header->uh_dport = htons(atoi(argv[2]));
    udp_header->uh_ulen = htons(sizeof(struct udphdr));

    pseudo_header->ip_src.s_addr = ip_header->ip_src.s_addr;
    pseudo_header->ip_dst.s_addr = ip_header->ip_dst.s_addr;
    pseudo_header->unused = 0;
    pseudo_header->protocol = ip_header->ip_p;
    pseudo_header->length = udp_header->uh_ulen;
    
    udp_header->uh_sum = 0;
    checksum = internet_checksum((unsigned short *)udp_header, sizeof(struct udphdr) + sizeof(struct phdr));
    udp_header->uh_sum = (checksum == 0) ? 0xffff : checksum;

    fprintf(stdout, "Sending UDP packet...\n");
    print_hex(datagram, ip_header->ip_len);

    for (;;) {
        retval = sendto(sockfd, datagram, ip_header->ip_len, 0, rp->ai_addr, rp->ai_addrlen);
        if (retval == -1) {
            perror("sendto()");
        }
        sleep(1);
    }

    exit(EXIT_SUCCESS);
}
