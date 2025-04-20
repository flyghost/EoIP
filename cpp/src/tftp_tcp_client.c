#include "tftp_stack.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1069
#define CLIENT_MAC {0x11,0x22,0x33,0x44,0x55,0x66}
#define CLIENT_IP 0xC0A80164 // 192.168.1.100
#define CLIENT_PORT 54321

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connection failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 准备TFTP RRQ请求
    tftp_packet_t tftp_pkt;
    uint8_t options[] = "blksize 1024\0timeout 5\0";
    size_t tftp_len = tftp_build_rrq(&tftp_pkt, "test.txt", "octet", options);

    // 封装完整协议栈
    uint8_t packet[1500];
    uint8_t client_mac[] = CLIENT_MAC;
    uint8_t server_mac[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; // 初始用广播
    
    size_t pkt_len = encapsulate_tftp_packet(packet, sizeof(packet), &tftp_pkt,
                                           CLIENT_IP, 0xFFFFFFFF, // 广播IP
                                           CLIENT_PORT, 69,
                                           client_mac, server_mac);

    // 发送请求
    if (send(sockfd, packet, pkt_len, 0) != pkt_len) {
        perror("send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 接收响应
    uint8_t recv_buf[1500];
    ssize_t recv_len = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
    if (recv_len <= 0) {
        perror("recv failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 解析响应
    tftp_packet_t recv_pkt;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t src_mac[6], dst_mac[6];
    
    if (parse_tftp_packet(recv_buf, recv_len, &recv_pkt,
                         &src_ip, &dst_ip, &src_port, &dst_port,
                         src_mac, dst_mac) == 0) {
        printf("Received TFTP packet, opcode: %d\n", recv_pkt.opcode);
        
        if (recv_pkt.opcode == TFTP_OP_OACK) {
            printf("Options: %s\n", recv_pkt.oack.options);
            
            // 发送ACK(0)确认选项
            tftp_packet_t ack_pkt;
            tftp_build_ack(&ack_pkt, 0);
            
            pkt_len = encapsulate_tftp_packet(packet, sizeof(packet), &ack_pkt,
                                            CLIENT_IP, src_ip,
                                            CLIENT_PORT, src_port,
                                            client_mac, src_mac);
            
            send(sockfd, packet, pkt_len, 0);
        }
    }

    close(sockfd);
    return 0;
}