#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"


const char* MESSAGE = "Laboratorium PUS.";


int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    int server;
    int port;

    // Sprawdzanie czy podano wyamgany parametr z numerem portu
    if ( argc != 2 )
    {
        printf("Usage: %s <portnum>\n", argv[0]);
        exit(0);
    }
    port = atoi(argv[1]);

    // Inicjalizacja biblioteki SSL
    SSL_library_init();

    // Załadowanie tekstowych opisów błędów SSL
    SSL_load_error_strings();

    // Załadowanie algorytmów szyfrowania
    OpenSSL_add_all_algorithms();

    // Utworzenie kontekstu szyfrowania
    ctx = SSL_CTX_new(DTLS_server_method());
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }


    // Załadowanie z pliku certyfikatu i przypisanie do kontekstu
    if ( SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM) <= 0 )
    {
        // jeśli go nie ma, to możemy go wygenerować:
        // $ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.pem -out server.pem
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    // Załadowanie z pliku klucza prywatnego i przypisanie do kontekstu
    if ( SSL_CTX_use_PrivateKey_file(ctx, "server.pem", SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    // Weryfikacja, czy klucz prywatny pasuje do certyfikatu
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(0);
    }


    // Otwarcie socket do nasłuchiwania połączeń na porcie podanym w parametrze
    server = socket(PF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }

    if ( listen(server, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }

    printf("Noo, łącz się :)\n");
    
    // Pętla serwera odbierającego połączenia
    while (1)
    {
        // Odebranie połączenia na port TCP
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /*
         * Utworzenie struktury SSL. Konfiguracja jest kopiowana z kontekstu
         * i moze zostac zmieniona per-polaczenie.
         */
        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }


        /*
         * Powiazanie struktury SSL z deskryptorem pliku. Tworzony jest
         * "socket BIO" i bedzie on posredniczyl w operacjach I/O
         * miedzy ssl, a connfd:
         */
        if (SSL_set_fd(ssl, client) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        /* Oczekiwanie na inicjacje polaczenia TLS: */
        if ( SSL_accept(ssl) <= 0 ) {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            if (SSL_write(ssl, MESSAGE, strlen(MESSAGE)) <= 0) {
                ERR_print_errors_fp(stderr);
            }
        }

        // Zwolnienie zasobów
        SSL_free(ssl);

        // Zamkniecie połączenia z klientem
        close(client);

        printf("było git, następny :)\n");
    }

    // Zamknięcie socket na połączenia
    close(server);

    // Zwolnienie pamięci na kontekst
    SSL_CTX_free(ctx);
}

