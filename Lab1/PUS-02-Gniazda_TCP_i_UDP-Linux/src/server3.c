#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

extern int is_palindrome(const char *str); // Funkcja z libpalindrome.c

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr = {0}, client_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(atoi(argv[1]));

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %s...\n", argv[1]);

    char buffer[256];
    socklen_t client_len = sizeof(client_addr);
    while (1) {
        ssize_t received = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                                    (struct sockaddr *)&client_addr, &client_len);
        if (received <= 0) break;

        buffer[received] = '\0';
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Received from %s:%d - %s\n", client_ip, ntohs(client_addr.sin_port), buffer);

        char response[256];
        if (is_palindrome(buffer)) {
            snprintf(response, sizeof(response), "YES - It's a palindrome");
        } else {
            snprintf(response, sizeof(response), "NO - Not a palindrome");
        }

        sendto(sockfd, response, strlen(response), 0,
               (struct sockaddr *)&client_addr, client_len);
    }

    close(sockfd);
    return 0;
}
