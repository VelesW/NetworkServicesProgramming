#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024
#define IMG_DIR "img"

void *handle_client(void *arg);
char *generate_html();
char *get_mime_type(const char *filename);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int server_fd, client_fd, port = atoi(argv[1]);
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

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

    printf("Server listening on port %d...\n", port);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }

        pthread_t thread;
        int *pclient = malloc(sizeof(int));
        *pclient = client_fd;
        pthread_create(&thread, NULL, handle_client, pclient);
        pthread_detach(thread);
    }

    close(server_fd);
    return 0;
}

void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_fd);
        return NULL;
    }
    buffer[bytes_read] = '\0';

    char method[16], path[256];
    sscanf(buffer, "%15s %255s", method, path);

    if (strcmp(method, "GET") != 0) {
        close(client_fd);
        return NULL;
    }

    if (strncmp(path, "/img/", 5) == 0) {
        char filename[256];
        snprintf(filename, sizeof(filename), ".%s", path);
        int file_fd = open(filename, O_RDONLY);
        if (file_fd == -1) {
            close(client_fd);
            return NULL;
        }

        struct stat st;
        fstat(file_fd, &st);
        char response_header[BUFFER_SIZE];
        snprintf(response_header, sizeof(response_header),
                 "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\nContent-Type: %s\r\n\r\n",
                 st.st_size, get_mime_type(filename));
        send(client_fd, response_header, strlen(response_header), 0);
        sendfile(client_fd, file_fd, NULL, st.st_size);
        close(file_fd);
    } else {
        char *html_content = generate_html();
        char response_header[BUFFER_SIZE];
        snprintf(response_header, sizeof(response_header),
                 "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\nContent-Type: text/html\r\n\r\n",
                 strlen(html_content));
        send(client_fd, response_header, strlen(response_header), 0);
        send(client_fd, html_content, strlen(html_content), 0);
        free(html_content);
    }

    close(client_fd);
    return NULL;
}

char *generate_html() {
    DIR *dir = opendir(IMG_DIR);
    if (!dir) return strdup("<html><body><center><h1>No Images</h1></center></body></html>");

    char *html = malloc(BUFFER_SIZE);
    strcpy(html, "<html><body><center>");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".jpg") || strstr(entry->d_name, ".jpeg") ||
            strstr(entry->d_name, ".png") || strstr(entry->d_name, ".gif")) {
            char img_tag[256];
            snprintf(img_tag, sizeof(img_tag), "<img src=\"img/%s\"></img><br />", entry->d_name);
            strcat(html, img_tag);
        }
    }
    closedir(dir);
    strcat(html, "</center></body></html>");
    return html;
}

char *get_mime_type(const char *filename) {
    if (strstr(filename, ".jpg") || strstr(filename, ".jpeg")) return "image/jpeg";
    if (strstr(filename, ".png")) return "image/png";
    if (strstr(filename, ".gif")) return "image/gif";
    return "application/octet-stream";
}
