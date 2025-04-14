#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> /* socket() */
#include <netinet/in.h> /* struct sockaddr_in */
#include <arpa/inet.h>  /* inet_pton() */
#include <unistd.h>     /* close() */
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define MESSAGE "Laboratorium PUS."

int main(int argc, char** argv) {
    int             sockfd;                 /* Desktryptor gniazda. */
    int             retval;                 /* Wartosc zwracana przez funkcje. */
    struct          sockaddr_in remote_addr;/* Gniazdowa struktura adresowa. */
    socklen_t       addr_len;               /* Rozmiar struktury w bajtach. */
    
    /* Bufor na oryginalną wiadomość, szyfrogram oraz dane do wysłania */
    unsigned char plaintext[256] = MESSAGE;
    unsigned char ciphertext[256];
    unsigned char send_buffer[512]; /* Bufor na szyfrogram + HMAC */
    
    /* Rozmiary danych */
    int plaintext_len, ciphertext_len, tmp, hmac_len;
    int total_send_len = 0;
    
    /* Klucz i wektor inicjalizacyjny dla AES */
    unsigned char key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
                           0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
                           
    unsigned char iv[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
                          0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
                          
    /* Klucz HMAC */
    unsigned char hmac_key[] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    
    /* Konteksty dla szyfrowania i HMAC */
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER *cipher;
    EVP_MD_CTX *hmac_ctx;
    EVP_PKEY *hmac_pkey = NULL;
    const EVP_MD *md;
    
    /* Bufory dla HMAC */
    unsigned char hmac[EVP_MAX_MD_SIZE];

    if (argc != 3) {
        fprintf(stderr, "Invocation: %s <IPv4 ADDRESS> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Inicjalizacja biblioteki OpenSSL */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    /* Utworzenie gniazda dla protokolu UDP: */
    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    /* Wyzerowanie struktury adresowej dla adresu zdalnego (serwera): */
    memset(&remote_addr, 0, sizeof(remote_addr));
    /* Domena komunikacyjna (rodzina protokolow): */
    remote_addr.sin_family = AF_INET;

    /* Konwersja adresu IP z postaci kropkowo-dziesietnej: */
    retval = inet_pton(AF_INET, argv[1], &remote_addr.sin_addr);
    if (retval == 0) {
        fprintf(stderr, "inet_pton(): invalid network address!\n");
        exit(EXIT_FAILURE);
    } else if (retval == -1) {
        perror("inet_pton()");
        exit(EXIT_FAILURE);
    }

    remote_addr.sin_port = htons(atoi(argv[2])); /* Numer portu. */
    addr_len = sizeof(remote_addr); /* Rozmiar struktury adresowej w bajtach. */

    /* 1. Szyfrowanie wiadomości */
    cipher = EVP_aes_128_cbc();
    plaintext_len = strlen((char*)plaintext);
    
    /* Utworzenie i inicjalizacja kontekstu szyfrowania */
    cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_ctx);
    
    /* Konfiguracja kontekstu dla szyfrowania */
    retval = EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, iv);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Włączenie paddingu PKCS */
    EVP_CIPHER_CTX_set_padding(cipher_ctx, 1);
    
    /* Szyfrowanie */
    retval = EVP_EncryptUpdate(cipher_ctx, ciphertext, &ciphertext_len,
                              plaintext, plaintext_len);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Finalizacja szyfrowania */
    retval = EVP_EncryptFinal_ex(cipher_ctx, ciphertext + ciphertext_len, &tmp);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    ciphertext_len += tmp;
    
    /* Zwolnienie kontekstu szyfrowania */
    EVP_CIPHER_CTX_free(cipher_ctx);
    
    /* 2. Obliczenie HMAC dla szyfrogramu */
    md = EVP_sha256();  /* Używamy SHA-256 jako funkcji skrótu */
    
    /* Utworzenie klucza dla HMAC */
    hmac_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hmac_key, sizeof(hmac_key));
    if (!hmac_pkey) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Utworzenie kontekstu dla HMAC */
    hmac_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(hmac_ctx);
    
    /* Inicjalizacja kontekstu HMAC */
    retval = EVP_DigestSignInit(hmac_ctx, NULL, md, NULL, hmac_pkey);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Obliczenie HMAC */
    retval = EVP_DigestSignUpdate(hmac_ctx, ciphertext, ciphertext_len);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Zapisanie wielkości bufora */
    hmac_len = EVP_MAX_MD_SIZE;
    
    /* Uzyskanie wartości HMAC */
    retval = EVP_DigestSignFinal(hmac_ctx, hmac, (size_t*)&hmac_len);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Zwolnienie zasobów HMAC */
    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(hmac_pkey);
    
    /* 3. Przygotowanie danych do wysłania (format: [CIPHERTEXT_LEN][CIPHERTEXT][HMAC]) */
    
    /* Najpierw zapisujemy długość szyfrogramu (4 bajty) */
    memcpy(send_buffer, &ciphertext_len, sizeof(int));
    total_send_len += sizeof(int);
    
    /* Następnie kopiujemy szyfrogram */
    memcpy(send_buffer + total_send_len, ciphertext, ciphertext_len);
    total_send_len += ciphertext_len;
    
    /* Na końcu kopiujemy HMAC */
    memcpy(send_buffer + total_send_len, hmac, hmac_len);
    total_send_len += hmac_len;

    fprintf(stdout, "Sending encrypted message to %s.\n", argv[1]);
    fprintf(stdout, "Original message: %s\n", MESSAGE);
    fprintf(stdout, "Ciphertext length: %d bytes\n", ciphertext_len);
    fprintf(stdout, "HMAC length: %d bytes\n", hmac_len);
    fprintf(stdout, "Total data size: %d bytes\n", total_send_len);

    /* Wysłanie danych na adres określony przez strukturę 'remote_addr': */
    retval = sendto(
                 sockfd,
                 send_buffer, total_send_len,
                 0,
                 (struct sockaddr*)&remote_addr, addr_len
             );

    if (retval == -1) {
        perror("sendto()");
        exit(EXIT_FAILURE);
    }

    /* Zwolnienie zasobów OpenSSL */
    EVP_cleanup();
    ERR_free_strings();
    
    close(sockfd);
    exit(EXIT_SUCCESS);
}