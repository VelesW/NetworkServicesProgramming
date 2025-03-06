// server3.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "libpalindrome.h"

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr, client_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    socklen_t client_len = sizeof(client_addr);
    printf("Server is listening...\n");
    while (1) {
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (recv_len == 0)
            break;

        buffer[recv_len] = '\0';

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Received from %s:%d - %s\n", client_ip, ntohs(client_addr.sin_port), buffer);

        if (is_palindrome(buffer, recv_len)) {
            strcpy(buffer, "YES - it's a pallindrome\n");
        } else {
            strcpy(buffer, "NO - it isn't a pallindrome\n");
        }

        sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&client_addr, client_len);
    }

    close(sockfd);
    return 0;
}
