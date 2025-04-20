import socket
import struct
from datetime import datetime
import os
import sys
from pathlib import Path

# 将utils目录添加到Python路径
utils_path = Path(__file__).parent.parent.parent / 'utils'
sys.path.append(str(utils_path))

from protocol import Protocol
from packet_parser import PacketParser
from hex_printer import HexPrinter

class TftpClient:
    """TFTP客户端实现（支持广播发现服务器）"""
    
    def __init__(self, host='127.0.0.1', port=1069):
        """初始化客户端"""
        self.host = host
        self.port = port
        self.sock = None
        self.block_size = 1024
        self.timeout = 5.0
        self.retries = 3
        self.sequence = 0
        
        # 动态获取的服务器参数
        self.server_mac = None    # 将从响应中获取
        self.server_ip = None     # 将从响应中获取
        self.server_port = None   # 将从响应中获取
        
        # 客户端网络参数
        self.src_mac = '11:22:33:44:55:66'  # 客户端MAC
        self.src_ip = '192.168.1.100'       # 客户端IP
        self.src_port = 54321               # 客户端端口

    def connect(self):
        """连接到TFTP桥接服务"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        print(f"[{datetime.now()}] 已连接到 Bridge {self.host}:{self.port}")

    def disconnect(self):
        """断开连接并清理资源"""
        if self.sock:
            self.sock.close()
            print(f"[{datetime.now()}] 已断开连接")

    def create_ethernet_frame(self, payload, broadcast=False):
        """创建以太网帧"""
        dst_mac = bytes.fromhex('ff:ff:ff:ff:ff:ff'.replace(':', '')) if broadcast else (
            bytes.fromhex(self.server_mac.replace(':', '')) if self.server_mac 
            else bytes.fromhex('ff:ff:ff:ff:ff:ff'.replace(':', ''))
        )
        src_mac = bytes.fromhex(self.src_mac.replace(':', ''))
        return Protocol.ETH_HEADER.pack(dst_mac, src_mac, 0x0800) + payload

    def create_ip_packet(self, payload, broadcast=False):
        """创建IP数据包"""
        version_ihl = 0x45
        dscp_ecn = 0
        total_length = 20 + 8 + len(payload)
        identification = 54321
        flags_frag = 0
        ttl = 64
        protocol = 17  # UDP
        checksum = 0
        src_ip = socket.inet_aton(self.src_ip)
        dst_ip = socket.inet_aton('255.255.255.255' if broadcast else (
            self.server_ip if self.server_ip else '255.255.255.255'
        ))
        
        return Protocol.IP_HEADER.pack(
            version_ihl, dscp_ecn, total_length,
            identification, flags_frag, ttl,
            protocol, checksum, src_ip, dst_ip
        ) + payload

    def create_udp_packet(self, payload, src_port, dst_port):
        """创建UDP数据包"""
        length = 8 + len(payload)
        checksum = 0
        return Protocol.UDP_HEADER.pack(src_port, dst_port, length, checksum) + payload

    def create_tftp_packet(self, opcode, block_num=0, data=b'', filename='', options=None):
        """创建TFTP协议数据包"""
        if opcode == Protocol.TFTP_OP_RRQ or opcode == Protocol.TFTP_OP_WRQ:
            packet = struct.pack('!H', opcode) + filename.encode() + b'\x00' + Protocol.MODE_OCTET + b'\x00'
            if options:
                for key, value in options.items():
                    packet += key.encode('ascii') + b'\x00' + str(value).encode('ascii') + b'\x00'
            return packet
        elif opcode == Protocol.TFTP_OP_ACK:
            return struct.pack('!HH', opcode, block_num)
        elif opcode == Protocol.TFTP_OP_ERROR:
            return struct.pack('!HH', opcode, block_num) + data.encode('ascii') + b'\x00'
        raise ValueError(f"无效的TFTP操作码: {opcode}")

    def parse_response(self, data):
        """解析服务器响应"""
        print(f"\n[{datetime.now()}] 收到响应 ({len(data)} 字节)")
        HexPrinter.print_hex(data)
        
        # 解析协议栈
        eth_info = PacketParser.parse_ethernet_frame(data)
        if not eth_info:
            return None, None, None
            
        ip_info = PacketParser.parse_ip_packet(data[14:])
        if not ip_info or ip_info['protocol'] != 17:
            return None, None, None
            
        udp_info = PacketParser.parse_udp_packet(data[14+20:])
        if not udp_info:
            return None, None, None
            
        # 记录服务器地址信息(第一次响应时)
        if not self.server_mac:
            self.server_mac = eth_info['src_mac']
            self.server_ip = ip_info['src_ip']
            self.server_port = udp_info['src_port']
            print(f"[{datetime.now()}] 发现TFTP服务器: MAC={self.server_mac}, IP={self.server_ip}, Port={self.server_port}")
        
        # 解析TFTP数据
        tftp_payload = data[14+20+8:]
        tftp_info = PacketParser.parse_tftp_packet(tftp_payload)
        if not tftp_info:
            return None, None, None
            
        return tftp_info['opcode'], tftp_payload, udp_info['src_port']

    def send_rrq(self, remote_filename, options=None):
        """发送读取请求(RRQ) - 使用广播"""
        options = options or {}
        rrq_packet = self.create_tftp_packet(
            opcode=Protocol.TFTP_OP_RRQ,
            filename=remote_filename,
            options=options
        )
        # 第一次发送使用广播
        udp_packet = self.create_udp_packet(rrq_packet, self.src_port, 69)
        ip_packet = self.create_ip_packet(udp_packet, broadcast=True)
        eth_frame = self.create_ethernet_frame(ip_packet, broadcast=True)
        
        self.sock.sendall(eth_frame)
        self.sequence += 1
        
        print(f"\n[{datetime.now()}] #{self.sequence} 发送广播请求 ({len(eth_frame)} 字节)")
        HexPrinter.print_hex(eth_frame)

    def send_packet(self, payload, dst_port=None):
        """发送数据包(非初始请求)"""
        if not dst_port:
            if not self.server_port:
                raise ValueError("未获取服务器端口")
            dst_port = self.server_port
            
        udp_packet = self.create_udp_packet(payload, self.src_port, dst_port)
        ip_packet = self.create_ip_packet(udp_packet)
        eth_frame = self.create_ethernet_frame(ip_packet)
        
        self.sock.sendall(eth_frame)
        self.sequence += 1
        
        print(f"\n[{datetime.now()}] #{self.sequence} 发送数据包 ({len(eth_frame)} 字节)")
        HexPrinter.print_hex(eth_frame)

    def send_ack(self, block_num):
        """发送确认(ACK)"""
        if not self.server_port:
            raise ValueError("未获取服务器端口")
            
        ack_packet = self.create_tftp_packet(
            opcode=Protocol.TFTP_OP_ACK,
            block_num=block_num
        )
        print(f"\n[{datetime.now()}] 发送ACK #{block_num} ({len(ack_packet)} 字节)")
        HexPrinter.print_hex(ack_packet)
        self.send_packet(ack_packet)

    def handle_data(self, block_num, data):
        """处理数据块"""
        if len(data) > self.block_size:
            raise ValueError("数据块大小超过限制")
            
        return data

    def _parse_block_size(self, blksize_str):
        """解析块大小选项"""
        try:
            blksize = int(blksize_str) if blksize_str else self.block_size
            return min(max(blksize, 8), 65464)  # RFC 2348限制
        except ValueError:
            return self.block_size
        
    def download_file(self, remote_filename, local_filename, options=None):
        """下载文件（完整实现）"""
        options = options or {}
        try:
            self.connect()
            self.send_rrq(remote_filename, options)
            expected_block = 1  # 初始期望块号为1
            block_size = self._parse_block_size(options.get('blksize'))

            with open(local_filename, 'wb') as f:
                for attempt in range(self.retries + 1):
                    try:
                        data = self.sock.recv(2048)
                        if not data:
                            break

                        opcode, payload, _ = self.parse_response(data)
                        if opcode is None:
                            continue

                        if opcode == Protocol.TFTP_OP_OACK:
                            # 处理服务器OACK响应
                            print(f"[{datetime.now()}] 服务器接受选项: {payload}")
                            self.send_ack(0)  # 发送ACK 0确认选项
                            continue
                            
                        if opcode == Protocol.TFTP_OP_DATA:
                            tftp_info = PacketParser.parse_tftp_packet(payload)
                            recv_block = tftp_info['block_num']
                            file_data = tftp_info['data']

                            if recv_block == expected_block:
                                f.write(self.handle_data(recv_block, file_data))
                                self.send_ack(recv_block)
                                expected_block += 1

                                # 检查传输是否完成
                                if len(file_data) < block_size:
                                    print(f"[{datetime.now()}] 下载完成: {local_filename}")
                                    return True

                            elif recv_block < expected_block:
                                # 重复数据块，重新发送ACK
                                self.send_ack(recv_block)
                            else:
                                print(f"[{datetime.now()}] 收到乱序块: 期望 #{expected_block}, 实际 #{recv_block}")
                                break

                        elif opcode == Protocol.TFTP_OP_ERROR:
                            tftp_info = PacketParser.parse_tftp_packet(payload)
                            print(f"[{datetime.now()}] 服务器错误: {tftp_info['error_msg']}")
                            return False

                    except socket.timeout:
                        if attempt == self.retries:
                            print(f"[{datetime.now()}] 达到最大重试次数")
                            return False
                        print(f"[{datetime.now()}] 超时，重试 {attempt + 1}/{self.retries}")
                        continue

        except Exception as e:
            print(f"[{datetime.now()}] 错误: {e}")
            return False
        finally:
            self.disconnect()
        return False

def main():
    # 示例用法
    client = TftpClient('127.0.0.1', 1069)
    options = {'blksize': '1024', 'timeout': '10'}
    if client.download_file('test.txt', 'downloaded.txt', options):
        print("文件下载成功")
    else:
        print("文件下载失败")

if __name__ == "__main__":
    main()