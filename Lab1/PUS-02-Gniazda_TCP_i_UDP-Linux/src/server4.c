#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/select.h>

#define MAX_CLIENTS  FD_SETSIZE
#define BUFFER_SIZE  256

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int server_fd, new_client, max_fd, port = atoi(argv[1]);
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    fd_set master_set, read_fds;
    char buffer[BUFFER_SIZE];

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    max_fd = server_fd;
    printf("Server listening on port %d...\n", port);

    while (1) {
        read_fds = master_set;
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        }

        for (int fd = 0; fd <= max_fd; fd++) {
            if (FD_ISSET(fd, &read_fds)) {
                if (fd == server_fd) {
                    client_len = sizeof(client_addr);
                    new_client = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
                    if (new_client == -1) {
                        perror("accept");
                        continue;
                    }

                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                    printf("New connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

                    FD_SET(new_client, &master_set);
                    if (new_client > max_fd) max_fd = new_client;
                } else {
                    ssize_t bytes_received = recv(fd, buffer, BUFFER_SIZE - 1, 0);
                    if (bytes_received <= 0) {
                        printf("Client disconnected: fd %d\n", fd);
                        close(fd);
                        FD_CLR(fd, &master_set);
                    } else {
                        buffer[bytes_received] = '\0';
                        printf("Message from fd %d: %s\n", fd, buffer);

                        for (int client_fd = 0; client_fd <= max_fd; client_fd++) {
                            if (FD_ISSET(client_fd, &master_set) && client_fd != server_fd && client_fd != fd) {
                                send(client_fd, buffer, bytes_received, 0);
                            }
                        }
                    }
                }
            }
        }
    }
    close(server_fd);
    return 0;
}
