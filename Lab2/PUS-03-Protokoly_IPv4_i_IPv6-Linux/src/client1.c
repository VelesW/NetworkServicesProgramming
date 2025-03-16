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

    if (argc != 3) {
        fprintf(stderr, "Invocation: %s <IPv6 ADDRESS> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sockfd = socket(PF_INET6, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin6_family = AF_INET6;

    retval = inet_pton(AF_INET6, argv[1], &remote_addr.sin6_addr);
    if (retval == 0) {
        fprintf(stderr, "inet_pton(): invalid network address!\n");
        exit(EXIT_FAILURE);
    } else if (retval == -1) {
        perror("inet_pton()");
        exit(EXIT_FAILURE);
    }

    remote_addr.sin6_port = htons(atoi(argv[2]));
    addr_len = sizeof(remote_addr);

    sleep(1);

    if (connect(sockfd, (const struct sockaddr*) &remote_addr, addr_len) == -1) {
        perror("connect()");
        exit(EXIT_FAILURE);
    }

    sleep(3);
    fprintf(stdout, "After three-way handshake. Waiting for server response...\n");

    memset(buff, 0, 256);
    retval = read(sockfd, buff, sizeof(buff));
    sleep(1);
    fprintf(stdout, "Received server response: %s\n", buff);

    sleep(4);
    fprintf(stdout, "Closing socket (sending FIN to server)...\n");
    close(sockfd);

    sleep(9);
    fprintf(stdout, "Terminating application. TCP connection will go into TIME_WAIT state.\n");

    sleep(4);
    exit(EXIT_SUCCESS);
}