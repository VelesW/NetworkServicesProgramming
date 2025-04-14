#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> /* socket() */
#include <netinet/in.h> /* struct sockaddr_in */
#include <arpa/inet.h>  /* inet_ntop() */
#include <unistd.h>     /* close() */
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int main(int argc, char** argv) {
    int             sockfd; /* Deskryptor gniazda. */
    int             retval; /* Wartosc zwracana przez funkcje. */

    /* Gniazdowe struktury adresowe (dla klienta i serwera): */
    struct          sockaddr_in client_addr, server_addr;

    /* Rozmiar struktur w bajtach: */
    socklen_t       client_addr_len, server_addr_len;

    /* Bufor wykorzystywany przez recvfrom(): */
    unsigned char   recv_buffer[512];
    
    /* Bufory na dane */
    unsigned char   ciphertext[256];
    unsigned char   plaintext[256];
    unsigned char   received_hmac[EVP_MAX_MD_SIZE];
    unsigned char   calculated_hmac[EVP_MAX_MD_SIZE];
    
    /* Rozmiary danych */
    int ciphertext_len, plaintext_len, tmp;
    int hmac_len = 32; /* SHA-256 tworzy 32-bajtowy HMAC */
    size_t calc_hmac_len;
    
    /* Bufor dla adresu IP klienta w postaci kropkowo-dziesietnej: */
    char            addr_buff[256];
    
    /* Klucz i wektor inicjalizacyjny dla AES (takie same jak w kliencie) */
    unsigned char key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
                          0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
                          
    unsigned char iv[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
                         0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
                         
    /* Klucz HMAC */
    unsigned char hmac_key[] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    
    /* Konteksty dla deszyfrowania i HMAC */
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER *cipher;
    EVP_MD_CTX *hmac_ctx;
    EVP_PKEY *hmac_pkey = NULL;
    const EVP_MD *md;

    if (argc != 2) {
        fprintf(stderr, "Invocation: %s <PORT>\n", argv[0]);
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

    /* Wyzerowanie struktury adresowej serwera: */
    memset(&server_addr, 0, sizeof(server_addr));
    /* Domena komunikacyjna (rodzina protokolow): */
    server_addr.sin_family          =       AF_INET;
    /* Adres nieokreslony (ang. wildcard address): */
    server_addr.sin_addr.s_addr     =       htonl(INADDR_ANY);
    /* Numer portu: */
    server_addr.sin_port            =       htons(atoi(argv[1]));
    /* Rozmiar struktury adresowej serwera w bajtach: */
    server_addr_len                 =       sizeof(server_addr);

    /* Powiazanie "nazwy" (adresu IP i numeru portu) z gniazdem: */
    if (bind(sockfd, (struct sockaddr*) &server_addr, server_addr_len) == -1) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Server is waiting for UDP datagram...\n");

    client_addr_len = sizeof(client_addr);

    /* Oczekiwanie na dane od klienta: */
    retval = recvfrom(
                 sockfd,
                 recv_buffer, sizeof(recv_buffer),
                 0,
                 (struct sockaddr*)&client_addr, &client_addr_len
             );
    if (retval == -1) {
        perror("recvfrom()");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "UDP datagram received from %s:%d.\n",
            inet_ntop(AF_INET, &client_addr.sin_addr, addr_buff, sizeof(addr_buff)),
            ntohs(client_addr.sin_port)
           );
           
    /* 1. Rozpakowujemy dane z bufora (format: [CIPHERTEXT_LEN][CIPHERTEXT][HMAC]) */
    
    /* Odczytujemy długość szyfrogramu */
    memcpy(&ciphertext_len, recv_buffer, sizeof(int));
    
    /* Kopiujemy szyfrogram */
    memcpy(ciphertext, recv_buffer + sizeof(int), ciphertext_len);
    
    /* Kopiujemy otrzymany HMAC */
    memcpy(received_hmac, recv_buffer + sizeof(int) + ciphertext_len, hmac_len);
    
    fprintf(stdout, "Received ciphertext length: %d bytes\n", ciphertext_len);
    
    /* 2. Weryfikacja HMAC */
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
    
    /* Ustawienie początkowego rozmiaru bufora */
    calc_hmac_len = EVP_MAX_MD_SIZE;
    
    /* Uzyskanie wartości HMAC */
    retval = EVP_DigestSignFinal(hmac_ctx, calculated_hmac, &calc_hmac_len);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Zwolnienie zasobów HMAC */
    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(hmac_pkey);
    
    /* Porównanie obliczonego HMAC z otrzymanym */
    if (memcmp(calculated_hmac, received_hmac, hmac_len) != 0) {
        fprintf(stdout, "HMAC verification FAILED! Message could be tampered with.\n");
        /* Zwalnianie zasobów i zakończenie */
        EVP_cleanup();
        ERR_free_strings();
        close(sockfd);
        exit(EXIT_FAILURE);
    } else {
        fprintf(stdout, "HMAC verification successful. Message integrity confirmed.\n");
    }
    
    /* 3. Deszyfrowanie */
    cipher = EVP_aes_128_cbc();
    
    /* Utworzenie i inicjalizacja kontekstu deszyfrowania */
    cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_ctx);
    
    /* Konfiguracja kontekstu dla deszyfrowania */
    retval = EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key, iv);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Włączenie paddingu PKCS */
    EVP_CIPHER_CTX_set_padding(cipher_ctx, 1);
    
    /* Deszyfrowanie */
    retval = EVP_DecryptUpdate(cipher_ctx, plaintext, &plaintext_len,
                              ciphertext, ciphertext_len);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    /* Finalizacja deszyfrowania */
    retval = EVP_DecryptFinal_ex(cipher_ctx, plaintext + plaintext_len, &tmp);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    plaintext_len += tmp;
    /* Dodanie NULL na końcu, aby móc wyświetlić jako string */
    plaintext[plaintext_len] = '\0';
    
    /* Zwolnienie kontekstu deszyfrowania */
    EVP_CIPHER_CTX_free(cipher_ctx);

    fprintf(stdout, "Decrypted message: %s\n", plaintext);
    
    /* Zwolnienie zasobów OpenSSL */
    EVP_cleanup();
    ERR_free_strings();

    close(sockfd);
    exit(EXIT_SUCCESS);
}