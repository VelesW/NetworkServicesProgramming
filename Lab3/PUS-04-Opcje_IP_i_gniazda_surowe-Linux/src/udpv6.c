#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SOURCE_PORT 5050

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IPv6 ADDRESS> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sockfd;
    struct sockaddr_in6 dest_addr;

    // Create a UDP socket
    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    // Fill in the destination address structure
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    dest_addr.sin6_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET6, argv[1], &dest_addr.sin6_addr) != 1) {
        perror("inet_pton()");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Sending UDPv6 packets to %s:%s...\n", argv[1], argv[2]);

    // Send empty UDP datagrams every second
    while (1) {
        if (sendto(sockfd, NULL, 0, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto()");
        }
        sleep(1);
    }

    close(sockfd);
    return 0;
}