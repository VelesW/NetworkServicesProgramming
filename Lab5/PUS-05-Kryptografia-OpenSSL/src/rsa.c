#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

int main(int argc, char **argv) {

    // Domyslny kontekst OpenSSL, tu zosanie NULL
    OSSL_LIB_CTX *libctx = NULL;

    // Kontekst generatora kluczy, jego zainicjalizujemy potem
    EVP_PKEY_CTX *genctx = NULL;

    /* Wartosc zwracana przez funkcje: */
    int retval;

    /* Wskaznik na plik: */
    FILE *file;

    /* Wskaznik na strukture przechowujaca pare kluczy RSA: */
    EVP_PKEY *pkey = NULL;
    BIGNUM *bne = BN_new();
    retval = BN_set_word(bne, 65537);
    if (retval != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Zaladowanie tekstowych opisow bledow: */
    ERR_load_crypto_strings();

    /*
     * Inicjalizacja generatora liczb pseudolosowych za pomoca pliku
     * /dev/urandom:
     */
    RAND_load_file("/dev/urandom", 1024);

    /* Wygenerowanie kluczy: */
    // teraz inicjalizujemy ten kontekst
    genctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if (genctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        exit(EXIT_FAILURE);
    }

    // tzn. teraz inicjalizujemy, tam wyzej to byla alokacja pamieci
    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init() failed\n");
        exit(EXIT_FAILURE);
    }

    // ustawiamy, zeby klucz mial 4096 bitow dlugosci
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, 4096) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits() failed\n");
        exit(EXIT_FAILURE);
    }

    // ustawiamy, ze ma uzywac dwoch liczb pierwszych
    if (EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, 2) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_primes() failed\n");
        exit(EXIT_FAILURE);
    }

    // teraz generujemy klucz RSA
    fprintf(stderr, "Generating RSA key, this may take some time...\n");
    if (EVP_PKEY_generate(genctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate() failed\n");
        exit(EXIT_FAILURE);
    }

    /* Weryfikacja poprawnosci kluczy: */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    retval = EVP_PKEY_check(pctx);
    if (retval <= 0) {
        if (retval == -1) {
            ERR_print_errors_fp(stderr);
        }
        fprintf(stderr, "Problem with keys. They should be regenerated.\n");
        exit(EXIT_FAILURE);
    }
    EVP_PKEY_CTX_free(pctx);

    /* Otworzenie pliku do zapisu: */
    file = fopen("public.key", "w");
    if (file == NULL) {
        perror("fopen()");
        exit(EXIT_FAILURE);
    }

    /* Zapisanie klucza publicznego w formacie PEM (kodowanie Base64) do pliku: */
    retval = PEM_write_PUBKEY(file, pkey);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    file = fopen("private.key", "w");
    if (file == NULL) {
        perror("fopen()");
        exit(EXIT_FAILURE);
    }

    /*
     * Zapisanie klucza prywatnego w formacie PEM do pliku.
     * Klucz jest szyfrowany za pomoca algorytmu AES.
     * Uzytkownik jest pytany o haslo, na podstawie ktorego zastanie wygenerowany
     * klucz dla szyfrowania symetrycznego.
     * Po zaszyfrowaniu klucza prywatnego RSA, jest on kodowany za pomoca Base64:
     */
    retval = PEM_write_PrivateKey(file, pkey, EVP_aes_256_cbc(),
                                     NULL, 0, NULL, NULL);
    if (!retval) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    /* Zwolnienie pamieci: */
    EVP_PKEY_free(pkey);

    /* Zwolnienie tekstowych opisow bledow: */
    ERR_free_strings();

    exit(EXIT_SUCCESS);
}
