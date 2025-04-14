#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#define BUFFER_SIZE 1024

// Struktura wiadomości
struct message {
    char text[BUFFER_SIZE];
    unsigned char signature[512]; // Zwiększamy bufor dla podpisu
    unsigned int signature_length;
};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Inicjalizacja biblioteki OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);

    // Utworzenie gniazda UDP
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(argv[1]));

    // Przypisanie adresu do gniazda
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    printf("Server started. Waiting for data...\n");

    // Wczytanie klucza publicznego OpenSSL 3.0
    EVP_PKEY *pkey = NULL;
    FILE *file = fopen("public.key", "r");
    if (!file) {
        perror("Unable to open public key file");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    if (!pkey) {
        fprintf(stderr, "Error reading public key\n");
        ERR_print_errors_fp(stderr);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Główna pętla serwera
    while (1) {
        // Odbiór danych
        struct message msg;
        socklen_t client_len = sizeof(client_addr);
        ssize_t recv_len;
        
        memset(&msg, 0, sizeof(msg)); // Zerowanie struktury przed odbiorem
        
        printf("Server is waiting for UDP datagram...\n");
        
        recv_len = recvfrom(sockfd, &msg, sizeof(msg), 0, 
                           (struct sockaddr *)&client_addr, &client_len);
        
        if (recv_len < 0) {
            perror("Error receiving data");
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("UDP datagram received from %s:%d.\n", 
               client_ip, ntohs(client_addr.sin_port));
        
        // Upewniamy się, że wiadomość jest zakończona zerem
        msg.text[BUFFER_SIZE - 1] = '\0';
        
        printf("Received message: %s\n", msg.text);
        printf("Signature length: %u\n", msg.signature_length);
        
        // Sprawdzenie poprawności długości podpisu
        int pkey_size = EVP_PKEY_size(pkey);
        if (msg.signature_length == 0 || msg.signature_length > (unsigned int)pkey_size) {
            printf("Invalid signature length\n");
            continue;
        }
        
        printf("Signature verification...\n");
        
        // Obliczenie skrótu wiadomości
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1((unsigned char *)msg.text, strlen(msg.text), hash);
        
        // Weryfikacja podpisu z API OpenSSL 3.0
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            fprintf(stderr, "Error creating EVP_MD_CTX\n");
            ERR_print_errors_fp(stderr);
            continue;
        }
        
        int result = 0;
        if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha1(), NULL, pkey) == 1) {
            // Weryfikacja bezpośrednio wiadomości zamiast skrótu
            result = EVP_DigestVerify(md_ctx, msg.signature, msg.signature_length, 
                                    (unsigned char *)msg.text, strlen(msg.text));
        }
        
        EVP_MD_CTX_free(md_ctx);
        
        // Wypisanie wyniku weryfikacji
        if (result == 1) {
            printf("Signature verified successfully!\n");
        } else {
            printf("Signature verification failed!\n");
            ERR_print_errors_fp(stderr);
        }
    }

    // Zwolnienie zasobów
    EVP_PKEY_free(pkey);
    close(sockfd);
    
    // Czyszczenie OpenSSL
    OPENSSL_cleanup();

    return 0;
}