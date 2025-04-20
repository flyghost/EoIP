import struct
import socket
from protocol import Protocol

class PacketBuilder(Protocol):
    """网络数据包构建工具 (继承自Protocol类获取常量)"""
    
    @staticmethod
    def build_ethernet_frame(src_mac, dst_mac, payload, ethertype=0x0800):
        """
        构建以太网帧
        :param src_mac: 源MAC地址 (格式如 "00:11:22:33:44:55")
        :param dst_mac: 目标MAC地址
        :param payload: 上层协议负载数据
        :param ethertype: 以太网类型 (默认0x0800表示IPv4)
        :return: 完整的以太网帧字节流
        """
        # 将MAC地址字符串转换为字节
        src_bytes = bytes.fromhex(src_mac.replace(':', ''))
        dst_bytes = bytes.fromhex(dst_mac.replace(':', ''))
        
        # 组装以太网帧头 + 负载
        return Protocol.ETH_HEADER.pack(dst_bytes, src_bytes, ethertype) + payload

    @staticmethod
    def build_ip_packet(src_ip, dst_ip, payload, protocol=17):
        """
        构建IP数据包
        :param src_ip: 源IP地址 (格式如 "192.168.1.1")
        :param dst_ip: 目标IP地址
        :param payload: 上层协议负载数据
        :param protocol: 协议类型 (默认17表示UDP)
        :return: 完整的IP数据包字节流
        """
        version_ihl = 0x45  # IPv4 + 头长度20字节
        total_length = 20 + len(payload)  # IP头 + 数据
        
        ip_header = Protocol.IP_HEADER.pack(
            version_ihl, 0, total_length,  # 版本/服务类型/总长度
            54321, 0,  # 标识符/标志和片偏移
            64, protocol, 0,  # TTL/协议/校验和
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
        )
        return ip_header + payload

    @staticmethod
    def build_udp_packet(src_port, dst_port, payload):
        """
        构建UDP数据包
        :param src_port: 源端口号
        :param dst_port: 目标端口号
        :param payload: 上层协议负载数据
        :return: 完整的UDP数据包字节流
        """
        length = 8 + len(payload)  # UDP头 + 数据
        return Protocol.UDP_HEADER.pack(src_port, dst_port, length, 0) + payload

    @staticmethod
    def build_tftp_packet(opcode, ​**kwargs):
        """
        构建TFTP协议数据包
        :param opcode: 操作码 (RRQ/WRQ/DATA/ACK/ERROR/OACK)
        :param kwargs: 根据操作码需要的参数:
            - RRQ/WRQ: filename, mode, options
            - DATA: block_num, data
            - ACK: block_num
            - ERROR: error_code, error_msg
            - OACK: options
        :return: TFTP协议数据字节流
        """
        if opcode in (Protocol.TFTP_OP_RRQ, Protocol.TFTP_OP_WRQ):
            packet = struct.pack('!H', opcode) + \
                   kwargs['filename'].encode('ascii') + b'\x00' + \
                   kwargs.get('mode', b'octet') + b'\x00'
            
            # 添加选项
            options = kwargs.get('options', {})
            for key, value in options.items():
                packet += key.encode('ascii') + b'\x00' + str(value).encode('ascii') + b'\x00'
            return packet
            
        elif opcode == Protocol.TFTP_OP_OACK:
            packet = struct.pack('!H', opcode)
            options = kwargs.get('options', {})
            for key, value in options.items():
                packet += key.encode('ascii') + b'\x00' + str(value).encode('ascii') + b'\x00'
            return packet
            
        elif opcode == Protocol.TFTP_OP_DATA:
            return struct.pack('!HH', opcode, kwargs['block_num']) + kwargs['data']
            
        elif opcode == Protocol.TFTP_OP_ACK:
            return struct.pack('!HH', opcode, kwargs['block_num'])
            
        elif opcode == Protocol.TFTP_OP_ERROR:
            return struct.pack('!HH', opcode, kwargs['error_code']) + \
                   kwargs['error_msg'].encode('ascii') + b'\x00'
                   
        raise ValueError(f"无效的TFTP操作码: {opcode}")