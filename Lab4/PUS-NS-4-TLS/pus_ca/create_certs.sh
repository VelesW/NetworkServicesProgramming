#!/bin/sh

#Intencja jest, aby tworzone pliki mialy prawa dostepu 0600:
umask 0077

################################################################################
#                                      CA                                      #
################################################################################

# Utworzenie pary kluczy RSA dla CA:
openssl genrsa -f4 -rand /dev/urandom \
        -out private/ca_keypair.pem \
        -aes256 \
        -passout file:private/ca_passwd 2048

# Utworzenie certyfikatu self-signed:
openssl req -x509 -new -config openssl.cnf -extensions v3_ca \
        -key private/ca_keypair.pem -days 365 -rand /dev/urandom \
        -out ca_cert.pem \
        -subj /CN=CA/OU=Rektorat/O=PK/L=Krakow/ST=Malopolska/C=PL \
        -passin file:private/ca_passwd




################################################################################
#                                    SERWER                                    #
################################################################################

# Utworzenie pary kluczy RSA dla serwera:
openssl genrsa -aes256 -f4 -rand /dev/urandom \
        -out tmp/server_keypair.pem \
        -passout file:tmp/server_passwd 2048

# Utworzenie CSR (Certificate Signing Request) dla serwera:
openssl req -new -config openssl.cnf -key tmp/server_keypair.pem \
        -rand /dev/urandom -out tmp/server_req.pem \
        -subj /CN=Server/OU=WIiT/O=PK/L=Krakow/ST=Malopolska/C=PL \
        -passin file:tmp/server_passwd

# Utworzenie certyfikatu serwera:
openssl ca -config openssl.cnf -extensions server_cert\
        -in tmp/server_req.pem -out tmp/server_cert.pem -notext \
        -passin file:private/ca_passwd

# Utworzenie lancucha certyfikatow dla serwera:
cat tmp/server_cert.pem ca_cert.pem > tmp/server_chain.pem




################################################################################
#                                    KLIENT                                    #
################################################################################
# Utworzenie pary kluczy RSA dla klienta:
openssl genrsa -aes256 -f4 -rand /dev/urandom \
        -out tmp/client_keypair.pem \
        -passout file:tmp/client_passwd 2048

# Utworzenie CSR (Certificate Signing Request) dla klienta:
openssl req -new -config openssl.cnf -key tmp/client_keypair.pem \
        -rand /dev/urandom -out tmp/client_req.pem \
        -subj /CN=Client/OU=WIiT/O=PK/L=Krakow/ST=Malopolska/C=PL \
        -passin file:tmp/client_passwd

# Utworzenie certyfikatu klienta:
openssl ca -config openssl.cnf -in tmp/client_req.pem \
       -out tmp/client_cert.pem -notext \
       -passin file:private/ca_passwd

# Utworzenie lancucha certyfikatow dla klienta:
cat tmp/client_cert.pem ca_cert.pem > tmp/client_chain.pem

