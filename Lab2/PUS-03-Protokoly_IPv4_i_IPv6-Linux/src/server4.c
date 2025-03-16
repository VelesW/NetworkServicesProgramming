#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MESSAGE "Laboratorium PUS"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Użycie: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char client_ip[INET_ADDRSTRLEN];

    // Tworzenie gniazda IPv4
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Konfiguracja adresu serwera
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    // Przypisanie adresu do gniazda
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Nasłuchiwanie na połączenia
    if (listen(server_sock, 1) == -1) {
        perror("listen");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Serwer IPv4 nasłuchuje na porcie %d...\n", port);

    while (1) {
        // Akceptacja połączenia
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock == -1) {
            perror("accept");
            continue;
        }

        // Pobranie adresu klienta
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Połączono z klientem: %s, port %d\n", client_ip, ntohs(client_addr.sin_port));

        // Wysłanie wiadomości do klienta
        send(client_sock, MESSAGE, strlen(MESSAGE), 0);

        // Zamknięcie połączenia
        close(client_sock);
    }

    close(server_sock);
    return 0;
}
