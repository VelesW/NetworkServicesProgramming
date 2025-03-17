#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#define PACKET_SIZE 64

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    
    return result;
}

void send_ping(int sockfd, struct sockaddr_in *addr, pid_t pid) {
    struct icmp packet;
    memset(&packet, 0, sizeof(packet));
    packet.icmp_type = ICMP_ECHO;
    packet.icmp_code = 0;
    packet.icmp_id = pid;
    
    srand(time(NULL));
    for (int i = 0; i < PACKET_SIZE - sizeof(struct icmp); i++)
        ((char *)&packet.icmp_data)[i] = 'A' + (rand() % 26);
    
    for (int i = 1; i <= 4; i++) {
        packet.icmp_seq = i;
        packet.icmp_cksum = 0;
        packet.icmp_cksum = checksum(&packet, sizeof(packet));
        
        if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)addr, sizeof(*addr)) < 0)
            perror("sendto");
        
        sleep(1);
    }
}

void recv_ping(int sockfd) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[1024];
    
    while (1) {
        ssize_t bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len);
        if (bytes < 0) {
            perror("recvfrom");
            continue;
        }
        
        struct ip *ip_hdr = (struct ip *)buffer;
        struct icmp *icmp_hdr = (struct icmp *)(buffer + (ip_hdr->ip_hl * 4));
        
        printf("Odebrano odpowiedź od %s\n", inet_ntoa(addr.sin_addr));
        printf("TTL: %d\n", ip_hdr->ip_ttl);
        printf("Rozmiar nagłówka IP: %d bajtów\n", ip_hdr->ip_hl * 4);
        printf("Adres docelowy: %s\n", inet_ntoa(ip_hdr->ip_dst));
        printf("ICMP - Typ: %d, Kod: %d, Identyfikator: %d, Sekwencja: %d\n", 
               icmp_hdr->icmp_type, icmp_hdr->icmp_code, ntohs(icmp_hdr->icmp_id), ntohs(icmp_hdr->icmp_seq));
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Użycie: %s <adres IP lub nazwa domenowa>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in addr;
    struct hostent *host;
    int sockfd;
    pid_t pid;
    
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    int ttl = 64;
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    if ((host = gethostbyname(argv[1])) == NULL) {
        perror("gethostbyname");
        exit(EXIT_FAILURE);
    }
    memcpy(&addr.sin_addr, host->h_addr, host->h_length);
    
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    
    if (pid == 0) {
        recv_ping(sockfd);
    } else {
        send_ping(sockfd, &addr, getpid());
    }
    
    close(sockfd);
    return 0;
}