#ifndef TFTP_STACK_H
#define TFTP_STACK_H

#include <stdint.h>
#include <stddef.h>

// 协议常量定义
#define TFTP_OP_RRQ   1
#define TFTP_OP_WRQ   2
#define TFTP_OP_DATA  3
#define TFTP_OP_ACK   4
#define TFTP_OP_ERROR 5
#define TFTP_OP_OACK  6

#define ETH_HEADER_SIZE 14
#define IP_HEADER_SIZE  20
#define UDP_HEADER_SIZE 8

// 链路层模块
typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
} eth_header_t;

void eth_build_header(eth_header_t *hdr, const uint8_t *dst_mac, 
                     const uint8_t *src_mac, uint16_t eth_type);
                     
// 网络层模块
typedef struct {
    uint8_t  version_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ip_header_t;

void ip_build_header(ip_header_t *hdr, uint32_t src_ip, uint32_t dst_ip, 
                    uint16_t payload_len, uint8_t protocol);

// 传输层模块
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

void udp_build_header(udp_header_t *hdr, uint16_t src_port, 
                     uint16_t dst_port, uint16_t payload_len);

// TFTP应用层模块
typedef struct {
    uint16_t opcode;
    union {
        struct {
            char filename[256];
            char mode[16];
            uint8_t options[256]; // blksize, timeout等
        } rrq_wrq;
        struct {
            uint16_t block_num;
            uint8_t  data[1024];
        } data;
        struct {
            uint16_t block_num;
        } ack;
        struct {
            uint16_t error_code;
            char error_msg[128];
        } error;
        struct {
            uint8_t options[256]; // 协商选项
        } oack;
    };
} tftp_packet_t;

size_t tftp_build_rrq(tftp_packet_t *pkt, const char *filename, 
                     const char *mode, const uint8_t *options);
size_t tftp_build_data(tftp_packet_t *pkt, uint16_t block_num, 
                      const uint8_t *data, size_t data_len);
size_t tftp_build_ack(tftp_packet_t *pkt, uint16_t block_num);
size_t tftp_build_oack(tftp_packet_t *pkt, const uint8_t *options);

// 协议栈封装模块
size_t encapsulate_tftp_packet(uint8_t *buffer, size_t buf_size,
                              const tftp_packet_t *tftp_pkt,
                              uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              const uint8_t *src_mac, const uint8_t *dst_mac);

int parse_tftp_packet(const uint8_t *data, size_t data_len,
                     tftp_packet_t *tftp_pkt,
                     uint32_t *src_ip, uint32_t *dst_ip,
                     uint16_t *src_port, uint16_t *dst_port,
                     uint8_t *src_mac, uint8_t *dst_mac);

#endif // TFTP_STACK_H