#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    while (1) {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);

        size_t len = strlen(buffer);
        if (buffer[len - 1] == '\n')
            buffer[len - 1] = '\0';

        if (strlen(buffer) == 0) {
            send(sockfd, "", 0, 0);
            break;
        }

        send(sockfd, buffer, strlen(buffer), 0);

        ssize_t recv_len = recv(sockfd, buffer, BUFFER_SIZE, 0);
        if (recv_len > 0) {
            buffer[recv_len] = '\0';
            printf("Server response: %s\n", buffer);
        }
    }

    close(sockfd);
    return 0;
}
