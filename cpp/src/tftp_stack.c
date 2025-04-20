#include "tftp_stack.h"
#include <string.h>
#include <arpa/inet.h>

// 链路层实现
void eth_build_header(eth_header_t *hdr, const uint8_t *dst_mac, 
                     const uint8_t *src_mac, uint16_t eth_type) {
    memcpy(hdr->dst_mac, dst_mac, 6);
    memcpy(hdr->src_mac, src_mac, 6);
    hdr->eth_type = htons(eth_type);
}

// 网络层实现
void ip_build_header(ip_header_t *hdr, uint32_t src_ip, uint32_t dst_ip, 
                    uint16_t payload_len, uint8_t protocol) {
    hdr->version_ihl = 0x45;
    hdr->dscp_ecn = 0;
    hdr->total_length = htons(IP_HEADER_SIZE + payload_len);
    hdr->identification = htons(54321);
    hdr->flags_frag = 0;
    hdr->ttl = 64;
    hdr->protocol = protocol;
    hdr->checksum = 0; // 实际实现应计算校验和
    hdr->src_ip = src_ip;
    hdr->dst_ip = dst_ip;
}

// 传输层实现
void udp_build_header(udp_header_t *hdr, uint16_t src_port, 
                     uint16_t dst_port, uint16_t payload_len) {
    hdr->src_port = htons(src_port);
    hdr->dst_port = htons(dst_port);
    hdr->length = htons(UDP_HEADER_SIZE + payload_len);
    hdr->checksum = 0; // UDP校验和可选
}

// TFTP应用层实现
size_t tftp_build_rrq(tftp_packet_t *pkt, const char *filename, 
                     const char *mode, const uint8_t *options) {
    pkt->opcode = htons(TFTP_OP_RRQ);
    strncpy(pkt->rrq_wrq.filename, filename, sizeof(pkt->rrq_wrq.filename)-1);
    strncpy(pkt->rrq_wrq.mode, mode, sizeof(pkt->rrq_wrq.mode)-1);
    
    size_t len = 2 + strlen(filename) + 1 + strlen(mode) + 1;
    if (options) {
        memcpy(pkt->rrq_wrq.options, options, strlen((char*)options));
        len += strlen((char*)options);
    }
    return len;
}

size_t tftp_build_data(tftp_packet_t *pkt, uint16_t block_num, 
                      const uint8_t *data, size_t data_len) {
    pkt->opcode = htons(TFTP_OP_DATA);
    pkt->data.block_num = htons(block_num);
    memcpy(pkt->data.data, data, data_len);
    return 4 + data_len;
}

size_t tftp_build_ack(tftp_packet_t *pkt, uint16_t block_num) {
    pkt->opcode = htons(TFTP_OP_ACK);
    pkt->ack.block_num = htons(block_num);
    return 4;
}

size_t tftp_build_oack(tftp_packet_t *pkt, const uint8_t *options) {
    pkt->opcode = htons(TFTP_OP_OACK);
    memcpy(pkt->oack.options, options, strlen((char*)options));
    return 2 + strlen((char*)options);
}

// 协议栈封装
size_t encapsulate_tftp_packet(uint8_t *buffer, size_t buf_size,
                              const tftp_packet_t *tftp_pkt,
                              uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              const uint8_t *src_mac, const uint8_t *dst_mac) {
    // 计算TFTP负载大小
    size_t tftp_len = 0;
    switch (ntohs(tftp_pkt->opcode)) {
        case TFTP_OP_RRQ:
            tftp_len = 2 + strlen(tftp_pkt->rrq_wrq.filename) + 1 + 
                      strlen(tftp_pkt->rrq_wrq.mode) + 1;
            if (tftp_pkt->rrq_wrq.options[0]) {
                tftp_len += strlen((char*)tftp_pkt->rrq_wrq.options);
            }
            break;
        case TFTP_OP_DATA:
            tftp_len = 4 + strlen((char*)tftp_pkt->data.data);
            break;
        case TFTP_OP_ACK:
            tftp_len = 4;
            break;
        case TFTP_OP_OACK:
            tftp_len = 2 + strlen((char*)tftp_pkt->oack.options);
            break;
    }

    // 构建UDP头
    udp_header_t udp_hdr;
    udp_build_header(&udp_hdr, src_port, dst_port, tftp_len);

    // 构建IP头
    ip_header_t ip_hdr;
    ip_build_header(&ip_hdr, src_ip, dst_ip, UDP_HEADER_SIZE + tftp_len, 17);

    // 构建以太网头
    eth_header_t eth_hdr;
    eth_build_header(&eth_hdr, dst_mac, src_mac, 0x0800);

    // 组装完整数据包
    size_t total_len = ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE + tftp_len;
    if (buf_size < total_len) return 0;

    uint8_t *ptr = buffer;
    memcpy(ptr, &eth_hdr, ETH_HEADER_SIZE); ptr += ETH_HEADER_SIZE;
    memcpy(ptr, &ip_hdr, IP_HEADER_SIZE); ptr += IP_HEADER_SIZE;
    memcpy(ptr, &udp_hdr, UDP_HEADER_SIZE); ptr += UDP_HEADER_SIZE;
    
    // 复制TFTP数据
    switch (ntohs(tftp_pkt->opcode)) {
        case TFTP_OP_RRQ: {
            *(uint16_t*)ptr = tftp_pkt->opcode; ptr += 2;
            strcpy((char*)ptr, tftp_pkt->rrq_wrq.filename); ptr += strlen(tftp_pkt->rrq_wrq.filename) + 1;
            strcpy((char*)ptr, tftp_pkt->rrq_wrq.mode); ptr += strlen(tftp_pkt->rrq_wrq.mode) + 1;
            if (tftp_pkt->rrq_wrq.options[0]) {
                strcpy((char*)ptr, (char*)tftp_pkt->rrq_wrq.options);
            }
            break;
        }
        case TFTP_OP_DATA: {
            *(uint16_t*)ptr = tftp_pkt->opcode; ptr += 2;
            *(uint16_t*)ptr = tftp_pkt->data.block_num; ptr += 2;
            memcpy(ptr, tftp_pkt->data.data, strlen((char*)tftp_pkt->data.data));
            break;
        }
        case TFTP_OP_ACK: {
            *(uint16_t*)ptr = tftp_pkt->opcode; ptr += 2;
            *(uint16_t*)ptr = tftp_pkt->ack.block_num; ptr += 2;
            break;
        }
        case TFTP_OP_OACK: {
            *(uint16_t*)ptr = tftp_pkt->opcode; ptr += 2;
            strcpy((char*)ptr, (char*)tftp_pkt->oack.options);
            break;
        }
    }

    return total_len;
}

// 协议解析
int parse_tftp_packet(const uint8_t *data, size_t data_len,
                     tftp_packet_t *tftp_pkt,
                     uint32_t *src_ip, uint32_t *dst_ip,
                     uint16_t *src_port, uint16_t *dst_port,
                     uint8_t *src_mac, uint8_t *dst_mac) {
    if (data_len < ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE + 2)
        return -1;

    // 解析以太网头
    const eth_header_t *eth_hdr = (const eth_header_t*)data;
    memcpy(dst_mac, eth_hdr->dst_mac, 6);
    memcpy(src_mac, eth_hdr->src_mac, 6);

    // 解析IP头
    const ip_header_t *ip_hdr = (const ip_header_t*)(data + ETH_HEADER_SIZE);
    *src_ip = ip_hdr->src_ip;
    *dst_ip = ip_hdr->dst_ip;

    // 解析UDP头
    const udp_header_t *udp_hdr = (const udp_header_t*)(data + ETH_HEADER_SIZE + IP_HEADER_SIZE);
    *src_port = ntohs(udp_hdr->src_port);
    *dst_port = ntohs(udp_hdr->dst_port);

    // 解析TFTP数据
    const uint8_t *tftp_data = data + ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
    tftp_pkt->opcode = ntohs(*(uint16_t*)tftp_data);

    switch (tftp_pkt->opcode) {
        case TFTP_OP_RRQ:
        case TFTP_OP_WRQ: {
            const char *ptr = (const char*)(tftp_data + 2);
            strncpy(tftp_pkt->rrq_wrq.filename, ptr, sizeof(tftp_pkt->rrq_wrq.filename)-1);
            ptr += strlen(tftp_pkt->rrq_wrq.filename) + 1;
            strncpy(tftp_pkt->rrq_wrq.mode, ptr, sizeof(tftp_pkt->rrq_wrq.mode)-1);
            ptr += strlen(tftp_pkt->rrq_wrq.mode) + 1;
            if (ptr < (const char*)(data + data_len)) {
                strncpy((char*)tftp_pkt->rrq_wrq.options, ptr, sizeof(tftp_pkt->rrq_wrq.options)-1);
            }
            break;
        }
        case TFTP_OP_DATA: {
            tftp_pkt->data.block_num = ntohs(*(uint16_t*)(tftp_data + 2));
            memcpy(tftp_pkt->data.data, tftp_data + 4, data_len - (ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE + 4));
            break;
        }
        case TFTP_OP_ACK: {
            tftp_pkt->ack.block_num = ntohs(*(uint16_t*)(tftp_data + 2));
            break;
        }
        case TFTP_OP_OACK: {
            strncpy((char*)tftp_pkt->oack.options, (const char*)(tftp_data + 2), sizeof(tftp_pkt->oack.options)-1);
            break;
        }
        default:
            return -1;
    }

    return 0;
}