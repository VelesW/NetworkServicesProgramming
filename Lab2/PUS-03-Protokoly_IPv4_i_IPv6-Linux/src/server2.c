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

    struct sockaddr_in6 client_addr, server_addr;
    socklen_t client_addr_len, server_addr_len;
    char buff[256];
    char addr_buff[INET6_ADDRSTRLEN];

    if (argc != 2) {
        fprintf(stderr, "Invocation: %s <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(atoi(argv[1]));

    server_addr_len = sizeof(server_addr);

    if (bind(sockfd, (struct sockaddr*)&server_addr, server_addr_len) == -1) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening for incoming UDP packets...\n");

    client_addr_len = sizeof(client_addr);

    retval = recvfrom(sockfd, buff, sizeof(buff), 0,
                      (struct sockaddr*)&client_addr, &client_addr_len);
    if (retval == -1) {
        perror("recvfrom()");
        exit(EXIT_FAILURE);
    }

    buff[retval] = '\0';

    printf("UDP datagram received from [%s]:%d. Echoing message...\n",
           inet_ntop(AF_INET6, &client_addr.sin6_addr, addr_buff, sizeof(addr_buff)),
           ntohs(client_addr.sin6_port));

    sleep(2);

    retval = sendto(sockfd, buff, retval, 0,
                    (struct sockaddr*)&client_addr, client_addr_len);
    if (retval == -1) {
        perror("sendto()");
        exit(EXIT_FAILURE);
    }

    close(sockfd);
    exit(EXIT_SUCCESS);
}