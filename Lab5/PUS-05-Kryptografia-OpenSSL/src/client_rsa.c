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
#include <openssl/bio.h>

#define BUFFER_SIZE 1024

// Struktura wiadomości
struct message {
    char text[BUFFER_SIZE];
    unsigned char signature[512]; // Zwiększamy bufor dla podpisu
    unsigned int signature_length;
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Inicjalizacja biblioteki OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);

    // Wczytanie klucza prywatnego OpenSSL 3.0
    EVP_PKEY *pkey = NULL;
    FILE *file = fopen("private.key", "r");
    if (!file) {
        perror("Unable to open private key file");
        exit(EXIT_FAILURE);
    }

    pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!pkey) {
        fprintf(stderr, "Error reading private key\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Utworzenie gniazda UDP
    int sockfd;
    struct sockaddr_in server_addr;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);
    server_addr.sin_port = htons(atoi(argv[2]));

    // Wiadomość do podpisania
    const char *message = "Laboratorium PUS.";
    
    // Przygotowanie struktury wiadomości
    struct message msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.text, message, sizeof(msg.text) - 1);
    
    // Tworzenie podpisu z EVP API (OpenSSL 3.0)
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha1(), NULL, pkey) != 1) {
        fprintf(stderr, "Error initializing signature\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    if (EVP_DigestSignUpdate(md_ctx, message, strlen(message)) != 1) {
        fprintf(stderr, "Error updating signature\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    size_t sig_len;
    // Najpierw określamy rozmiar podpisu
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) != 1) {
        fprintf(stderr, "Error determining signature length\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // Teraz generujemy faktyczny podpis
    if (sig_len > sizeof(msg.signature)) {
        fprintf(stderr, "Signature buffer too small\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    if (EVP_DigestSignFinal(md_ctx, msg.signature, &sig_len) != 1) {
        fprintf(stderr, "Error creating signature\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    msg.signature_length = (unsigned int)sig_len;
    EVP_MD_CTX_free(md_ctx);
    
    printf("Sending message: %s\n", message);
    printf("Signature length: %u bytes\n", msg.signature_length);
    
    // Wysłanie wiadomości i podpisu do serwera
    if (sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error sending data");
        EVP_PKEY_free(pkey);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Message and signature sent successfully.\n");

    // Zwolnienie zasobów
    EVP_PKEY_free(pkey);
    close(sockfd);
    
    // Czyszczenie OpenSSL
    OPENSSL_cleanup();

    return 0;
}

