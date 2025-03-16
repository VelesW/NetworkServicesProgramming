#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Użycie: %s <adres IPv6> <port> <interfejs>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    int port = atoi(argv[2]);
    char *interface_name = argv[3];

    int sock;
    struct sockaddr_in6 server_addr;
    char buffer[1024];

    // Tworzenie gniazda IPv6
    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Konfiguracja adresu serwera
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);

    if (inet_pton(AF_INET6, server_ip, &server_addr.sin6_addr) <= 0) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    // Pobranie indeksu interfejsu
    server_addr.sin6_scope_id = if_nametoindex(interface_name);
    if (server_addr.sin6_scope_id == 0) {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    // Połączenie z serwerem
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Odbiór wiadomości od serwera
    recv(sock, buffer, sizeof(buffer), 0);
    printf("Otrzymano od serwera: %s\n", buffer);

    // Zamknięcie połączenia
    close(sock);
    return 0;
}
