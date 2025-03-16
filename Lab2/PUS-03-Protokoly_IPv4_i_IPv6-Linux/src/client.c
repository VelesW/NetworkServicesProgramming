#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Użycie: %s <adres IP (IPv4 lub IPv6)> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    char *port = argv[2];
    int sock;
    struct addrinfo hints, *res, *p;
    struct sockaddr_storage local_addr;
    socklen_t addr_len = sizeof(local_addr);
    char host[NI_MAXHOST], service[NI_MAXSERV];
    char buffer[BUFFER_SIZE];

    // Inicjalizacja struktury hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Obsługuje zarówno IPv4, jak i IPv6
    hints.ai_socktype = SOCK_STREAM;

    // Pobranie informacji o adresie
    if (getaddrinfo(server_ip, port, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    // Przechodzimy przez listę adresów i próbujemy się połączyć
    for (p = res; p != NULL; p = p->ai_next) {
        // Tworzenie gniazda
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) continue;  // Próbujemy następny adres, jeśli nie uda się utworzyć gniazda

        // Próba połączenia z serwerem
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            printf("Połączono z serwerem!\n");
            break;  // Sukces, przerywamy pętlę
        }

        close(sock);  // Nie udało się połączyć, zamykamy gniazdo i próbujemy kolejny adres
    }

    freeaddrinfo(res);  // Zwolnienie pamięci zaalokowanej przez getaddrinfo

    if (p == NULL) {
        fprintf(stderr, "Nie udało się połączyć z serwerem\n");
        exit(EXIT_FAILURE);
    }

    // Pobranie lokalnego adresu gniazda
    if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) == -1) {
        perror("getsockname");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Wyświetlenie lokalnego adresu IP i portu
    if (getnameinfo((struct sockaddr *)&local_addr, addr_len, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        printf("Lokalny adres: %s, port: %s\n", host, service);
    } else {
        perror("getnameinfo");
    }

    // Odbiór wiadomości od serwera
    ssize_t bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Otrzymano od serwera: %s\n", buffer);
    } else {
        perror("recv");
    }

    // Zamknięcie połączenia
    close(sock);
    return 0;
}
