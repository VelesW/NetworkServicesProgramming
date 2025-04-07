PROJECT = 10
SYSTEM = linux
SRCDIR = src
BINDIR = bin
CC = gcc
CFLAGS = -O2 -pedantic -Wall

all: tcp_client tcp_server sslecho tls_client tls_server tls_client_check tls_server_check tls_client_both tls_server_both

files:
	@cp $(SRCDIR)/files/* $(BINDIR)/

clean:
	@rm -rf $(BINDIR)/*

distrib: clean
	tar -cvf $(SYSTEM)-$(PROJECT).tar $(SRCDIR)/* Makefile

tcp_client: tcp_client.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -o $(BINDIR)/$@

tcp_client.o: $(SRCDIR)/tcp_client.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o

tcp_server: tcp_server.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -o $(BINDIR)/$@

tcp_server.o: $(SRCDIR)/tcp_server.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o

sslecho: sslecho.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -o $(BINDIR)/$@ -lssl -lcrypto

sslecho.o: $(SRCDIR)/sslecho.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o


tls_client: tls_client.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -lssl -lcrypto -o $(BINDIR)/$@

tls_client.o: $(SRCDIR)/tls_client.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o

tls_server: tls_server.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -lssl -lcrypto -o $(BINDIR)/$@

tls_server.o: $(SRCDIR)/tls_server.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o


tls_client_check: tls_client_check.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -lssl -lcrypto -o $(BINDIR)/$@

tls_client_check.o: $(SRCDIR)/tls_client_check.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o

tls_server_check: tls_server_check.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -lssl -lcrypto -o $(BINDIR)/$@

tls_server_check.o: $(SRCDIR)/tls_server_check.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o



tls_client_both: tls_client_both.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -lssl -lcrypto -o $(BINDIR)/$@

tls_client_both.o: $(SRCDIR)/tls_client_both.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o

tls_server_both: tls_server_both.o
	$(CC) $(CFLAGS) $(BINDIR)/$@.o -lssl -lcrypto -o $(BINDIR)/$@

tls_server_both.o: $(SRCDIR)/tls_server_both.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/$(basename $@).c -o $(BINDIR)/$(basename $@).o

