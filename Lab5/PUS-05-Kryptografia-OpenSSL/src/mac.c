#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int main(int argc, char **argv) {

    /* Wartosc zwracana przez funkcje: */
    int retval;

    int i;

    /* Wiadomosc: */
    char message[64];

    /* HMAC wiadomosci: */
    unsigned char mac[EVP_MAX_MD_SIZE];

    /* Rozmiar tekstu i kodu MAC: */
    unsigned int message_len;
    size_t mac_len;  /* Zmieniono na size_t */

    /* Kontekst: */
    EVP_MD_CTX *ctx;

    /* Struktura przechowująca klucz: */
    EVP_PKEY *pkey = NULL;

    const EVP_MD* md;

    /* Klucz jako tablica bajtów: */
    unsigned char key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    size_t key_len = sizeof(key);

    if (argc != 2) {
        fprintf(stderr, "Invocation: %s <DIGEST NAME>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Zaladowanie tekstowych opisow bledow: */
    ERR_load_crypto_strings();

    /*
     * Zaladowanie nazw funkcji skrotu do pamieci.
     * Wymagane przez EVP_get_digestbyname():
     */
    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname(argv[1]);
    if (!md) {
        fprintf(stderr, "Unknown message digest: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    /* Pobranie maksymalnie 64 znakow ze standardowego wejscia: */
    if (fgets(message, 64, stdin) == NULL) {
        fprintf(stderr, "fgets() failed!\n");
        exit(EXIT_FAILURE);
    }

    message_len = strlen(message);

    /* Alokacja pamieci dla kontekstu: */
    ctx = EVP_MD_CTX_new();

    /* Inicjalizacja kontekstu: */
    EVP_MD_CTX_init(ctx);

    /* Parametry funkcji skrotu: */
    fprintf(stdout, "HMAC parameters:\n");
    fprintf(stdout, "Block size: %d bits\n", EVP_MD_block_size(md));
    fprintf(stdout, "Digest size: %d bytes\n\n", EVP_MD_size(md));
    
    /* Utworzenie klucza dla HMAC: */
    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Konfiguracja kontekstu do obliczenia HMAC: */
    retval = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Obliczenie HMAC: */
    retval = EVP_DigestSignUpdate(ctx, message, message_len);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Zapisanie HMAC w buforze 'mac': */
    mac_len = sizeof(mac);
    retval = EVP_DigestSignFinal(ctx, mac, &mac_len);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /*
     * Usuwa wszystkie informacje z kontekstu i zwalnia pamiec zwiazana
     * z kontekstem:
     */
    EVP_MD_CTX_free(ctx);
    
    /* Zwolnienie klucza: */
    EVP_PKEY_free(pkey);

    /* Usuniecie nazw funkcji skrotu z pamieci. */
    EVP_cleanup();

    fprintf(stdout, "HMAC (hex): ");
    for (i = 0; i < mac_len; i++) {
        fprintf(stdout, "%02x", mac[i]);
    }

    fprintf(stdout, "\n");

    /* Zwolnienie tekstowych opisow bledow: */
    ERR_free_strings();

    exit(EXIT_SUCCESS);
}