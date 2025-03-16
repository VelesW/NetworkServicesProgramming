#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

int main(int argc, char** argv) {
    int listenfd, connfd;
    int retval;
    struct sockaddr_in6 client_addr, server_addr;
    socklen_t client_addr_len, server_addr_len;
    char buff[256];
    char addr_buff[INET6_ADDRSTRLEN];
    time_t rawtime;
    struct tm* timeinfo;

    if (argc != 2) {
        fprintf(stderr, "Invocation: %s <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    listenfd = socket(PF_INET6, SOCK_STREAM, 0);
    if (listenfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(atoi(argv[1]));
    server_addr_len = sizeof(server_addr);

    if (bind(listenfd, (struct sockaddr*) &server_addr, server_addr_len) == -1) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    if (listen(listenfd, 2) == -1) {
        perror("listen()");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "IPv6 Server is listening for incoming connections...\n");

    client_addr_len = sizeof(client_addr);
    connfd = accept(listenfd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (connfd == -1) {
        perror("accept()");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "TCP connection accepted from %s:%d\n",
            inet_ntop(AF_INET6, &client_addr.sin6_addr, addr_buff, sizeof(addr_buff)),
            ntohs(client_addr.sin6_port));

    sleep(6);
    fprintf(stdout, "Sending current date and time...\n");

    sleep(2);
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S %Z", timeinfo);

    retval = write(connfd, buff, strlen(buff));

    retval = read(connfd, buff, sizeof(buff));
    if (retval == 0) {
        sleep(4);
        fprintf(stdout, "Connection terminated by client (received FIN)...\n");
    }

    sleep(12);
    fprintf(stdout, "Closing connected socket (sending FIN to client)...\n");
    close(connfd);

    sleep(5);
    fprintf(stdout, "Closing listening socket and terminating server...\n");
    close(listenfd);

    sleep(3);
    exit(EXIT_SUCCESS);
}