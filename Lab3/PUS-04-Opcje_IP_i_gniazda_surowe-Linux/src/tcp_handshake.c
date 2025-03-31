#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#define PSEUDO_HEADER_SIZE 12
#define SOURCE_ADDRESS "192.168.1.100" // Change to the correct source address

// Structure for the pseudo-header used for TCP checksum calculation
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Function to calculate the checksum
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

// Function to create and send a TCP packet
void send_tcp_packet(int sockfd, struct sockaddr_in *target, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags) {
    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));

    // Fill in the IP header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(packet));
    iph->ip_id = htons(rand() % 65535);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0; // Checksum will be calculated later
    iph->ip_src.s_addr = inet_addr(SOURCE_ADDRESS); // Change to the correct source address
    iph->ip_dst = target->sin_addr;

    // Fill in the TCP header
    tcph->th_sport = htons(src_port);
    tcph->th_dport = htons(dst_port);
    tcph->th_seq = htonl(seq);
    tcph->th_ack = htonl(ack);
    tcph->th_off = 5; // TCP header size
    tcph->th_flags = flags;
    tcph->th_win = htons(65535); // Maximum window size
    tcph->th_sum = 0; // Checksum will be calculated later
    tcph->th_urp = 0;

    // Create the pseudo-header for checksum calculation
    struct pseudo_header psh;
    psh.source_address = iph->ip_src.s_addr;
    psh.dest_address = iph->ip_dst.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Calculate the TCP checksum
    char pseudo_packet[PSEUDO_HEADER_SIZE + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, PSEUDO_HEADER_SIZE);
    memcpy(pseudo_packet + PSEUDO_HEADER_SIZE, tcph, sizeof(struct tcphdr));
    tcph->th_sum = checksum(pseudo_packet, PSEUDO_HEADER_SIZE + sizeof(struct tcphdr));

    // Send the packet
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        perror("sendto");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <port>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    uint16_t target_port = atoi(argv[2]);
    srand(time(NULL)); // Initialize random seed
    uint16_t source_port = rand() % 65535;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target.sin_addr);

    uint32_t seq = rand();

    // 1. Send SYN
    send_tcp_packet(sockfd, &target, source_port, target_port, seq, 0, TH_SYN);
    printf("Sent SYN to %s:%d\n", target_ip, target_port);
    
    sleep(1);

    // 2. Send ACK (assuming SYN-ACK was received)
    send_tcp_packet(sockfd, &target, source_port, target_port, seq + 1, seq + 1, TH_ACK);
    printf("Sent ACK to %s:%d\n", target_ip, target_port);
    
    sleep(2);

    // 3. Close connection: Send FIN
    send_tcp_packet(sockfd, &target, source_port, target_port, seq + 1, seq + 1, TH_FIN | TH_ACK);
    printf("Sent FIN to %s:%d\n", target_ip, target_port);

    sleep(1);

    close(sockfd);
    return 0;
}
