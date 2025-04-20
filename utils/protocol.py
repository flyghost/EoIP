import struct
import socket

class Protocol:
    """网络协议常量定义和基础方法"""
    
    # ========== TFTP协议常量 ==========
    TFTP_OP_RRQ = 1     # 读请求
    TFTP_OP_WRQ = 2     # 写请求
    TFTP_OP_DATA = 3    # 数据包
    TFTP_OP_ACK = 4     # 确认包
    TFTP_OP_ERROR = 5   # 错误包
    TFTP_OP_OACK = 6    # 选项确认 (RFC 2347)
    MODE_OCTET = b'octet'  # 传输模式

    # TFTP 操作码名称映射
    TFTP_OP_NAMES = {
        TFTP_OP_RRQ: "RRQ",
        TFTP_OP_WRQ: "WRQ",
        TFTP_OP_DATA: "DATA",
        TFTP_OP_ACK: "ACK",
        TFTP_OP_ERROR: "ERROR",
        TFTP_OP_OACK: "OACK"
    }

    # TFTP 选项
    OPTION_BLKSIZE = 'blksize'
    OPTION_TIMEOUT = 'timeout'
    OPTION_TSIZE = 'tsize'
    
    # ========== 协议头格式定义 ==========
    # 以太网帧头格式 (目标MAC 6字节 + 源MAC 6字节 + 类型2字节)
    ETH_HEADER = struct.Struct('!6s6sH')
    
    # IPv4头格式 (版本4位+头长度4位 | 服务类型 | 总长度 | 标识符 | 标志和片偏移 | TTL | 协议 | 校验和 | 源IP | 目标IP)
    IP_HEADER = struct.Struct('!BBHHHBBH4s4s')
    
    # UDP头格式 (源端口 | 目标端口 | 长度 | 校验和)
    UDP_HEADER = struct.Struct('!HHHH')
    
    @staticmethod
    def mac_to_str(mac_bytes):
        """将字节格式的MAC地址转换为可读字符串 (如 00:11:22:33:44:55)"""
        return ':'.join(f"{b:02x}" for b in mac_bytes)
    
    @staticmethod
    def ip_to_str(ip_bytes):
        """将字节格式的IP地址转换为可读字符串 (如 192.168.1.1)"""
        return socket.inet_ntoa(ip_bytes)