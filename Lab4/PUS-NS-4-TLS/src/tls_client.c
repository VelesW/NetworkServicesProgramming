#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 1024


int verify_callback(int status, X509_STORE_CTX *store) {

    char data[256];
    int depth;
    int err;

    if (!status) {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        depth = X509_STORE_CTX_get_error_depth(store);
        err = X509_STORE_CTX_get_error(store);

        fprintf(stderr, "Error with certificate at depth: %d\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr," ISSUER: %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr," SUBJECT: %s\n", data);

        fprintf(stderr," ERROR: %d:%s\n", err,
                X509_verify_cert_error_string(err));
    }

    return status;
}

int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int sock;
    SSL *ssl;
    char *hostname;
    int port;

    // Sprawdzanie czy podano wyamgane parametry z IP serwera i numerem portu
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    hostname=strings[1];
    port=atoi(strings[2]);

    // Inicjalizacja biblioteki SSL
    SSL_library_init();

    // Załadowanie tekstowych opisów błędów SSL
    SSL_load_error_strings();

    // Załadowanie algorytmów szyfrowania
    OpenSSL_add_all_algorithms();

    // Utworzenie kontekstu szyfrowania
    ctx = SSL_CTX_new(DTLS_client_method());
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }


    // Utworzenie socket i nawiązanie połączenia z serwerem na port TCP
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        exit(0);
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if ( connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sock);
        perror(hostname);
        exit(0);
    }

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
    if (SSL_set_fd(ssl, sock) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Oczekiwanie na inicjacje polaczenia TLS: */
    if ( SSL_connect(ssl) <= 0 ) {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        /* Odebranie danych: */
        char buff[BUF_SIZE];
        int bytes = 0;
        int total = 0;
        while ((bytes = SSL_read(ssl, buff + total, BUF_SIZE - total)) > 0) {
            total += bytes;
        }

        if (bytes < 0) {
            ERR_print_errors_fp(stderr);
        }

        fprintf(stdout, "Received message: ");
        fwrite(buff, sizeof(char), total, stdout);
        fprintf(stdout, "\n");
        
        // Zwolnienie zasobów
        SSL_free(ssl);
    }

    // Zamknięcie socket na połączenia
    close(sock);

    // Zwolnienie pamięci na kontekst
    SSL_CTX_free(ctx);

    return 0;
}

