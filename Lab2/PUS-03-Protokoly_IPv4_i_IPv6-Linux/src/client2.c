#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char** argv) {

    int sockfd;
    int retval;
    struct sockaddr_in6 remote_addr;
    socklen_t addr_len;
    char buff[256];

    if (argc != 4) {
        fprintf(stderr, "Invocation: %s <IPv6 ADDRESS> <PORT> <MESSAGE>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strlen(argv[3]) > 255) {
        fprintf(stdout, "Truncating message.\n");
        argv[3][255] = '\0';
    }

    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin6_family = AF_INET6;
    remote_addr.sin6_port = htons(atoi(argv[2]));

    retval = inet_pton(AF_INET6, argv[1], &remote_addr.sin6_addr);
    if (retval == 0) {
        fprintf(stderr, "inet_pton(): invalid IPv6 address!\n");
        exit(EXIT_FAILURE);
    } else if (retval == -1) {
        perror("inet_pton()");
        exit(EXIT_FAILURE);
    }

    addr_len = sizeof(remote_addr);

    printf("Sending message to [%s]:%s\n", argv[1], argv[2]);
    sleep(1);

    retval = sendto(sockfd, argv[3], strlen(argv[3]), 0,
                    (struct sockaddr*)&remote_addr, addr_len);
    if (retval == -1) {
        perror("sendto()");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for server response...\n");

    retval = recvfrom(sockfd, buff, sizeof(buff), 0, NULL, NULL);
    if (retval == -1) {
        perror("recvfrom()");
        exit(EXIT_FAILURE);
    }

    buff[retval] = '\0';
    printf("Server response: '%s'\n", buff);

    close(sockfd);
    exit(EXIT_SUCCESS);
}