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

class TFTPServer:
    def __init__(self, host='127.0.0.1', port=1069, base_dir='./tftp_root'):
        """..."""
        self.default_block_size = 512  # 默认块大小
        """
        初始化TFTP服务器
        :param host: 桥接服务地址
        :param port: 桥接服务端口
        :param base_dir: TFTP根目录
        """
        self.host = host
        self.port = port
        self.base_dir = base_dir
        self.sock = None
        self.transfers = {}  # 存储所有传输会话
        os.makedirs(base_dir, exist_ok=True)  # 确保根目录存在
        self.packet_count = 0  # 数据包计数器
        self.parser = PacketParser()  # 协议解析器实例
        self.last_src_mac = None  # 保存最后接收到的源MAC地址
        self.last_src_ip = None  # 保存最后接收到的源IP地址
        
        # 模拟网络参数
        self.src_mac = 'aa:bb:cc:dd:ee:ff'  # 服务器MAC
        self.src_ip = '192.168.1.1'         # 服务器IP
        self.src_port = 69                  # TFTP标准端口

    def connect_to_bridge(self):
        """连接到桥接服务"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[{datetime.now()}] TFTP Server 已连接到 Bridge {self.host}:{self.port}")

    def parse_packet(self, data):
        """
        解析网络数据包
        :param data: 原始网络数据
        :return: (src_mac, src_ip, src_port, tftp_data) 或 (None, None, None, None)
        """
        self.packet_count += 1
        print(f"\n[{datetime.now()}] 收到数据包 #{self.packet_count} ({len(data)} 字节)")
        
        HexPrinter.print_hex(data)  # 打印十六进制数据
        
        # 解析以太网帧
        eth = self.parser.parse_ethernet_frame(data)
        if not eth:
            print("  无效数据: 以太网帧解析失败")
            return None, None, None, None
            
        # 检查目标MAC是否是广播地址或服务器自己的MAC地址
        dst_mac = eth['dst_mac'].lower()
        server_mac = self.src_mac.lower()
        broadcast_mac = 'ff:ff:ff:ff:ff:ff'
        
        if dst_mac != broadcast_mac and dst_mac != server_mac:
            print(f"  忽略帧: 目标MAC {dst_mac} 不是广播地址或服务器MAC {server_mac}")
            return None, None, None, None
            
        if eth['ethertype'] != 0x0800:
            print("  无效数据: 不是IPv4数据包")
            return None, None, None, None
            
        # 解析IP数据包
        ip = self.parser.parse_ip_packet(data[14:])
        if not ip or ip['protocol'] != 17:  # 17 = UDP
            return None, None, None, None
            
        # 解析UDP数据包
        udp = self.parser.parse_udp_packet(data[14+20:])
        if not udp:
            return None, None, None, None
            
        # 保存源MAC和源IP地址用于回复
        self.last_src_mac = eth['src_mac']
        self.last_src_ip = ip['src_ip']
        tftp_data = data[14+20+8:]  # 提取TFTP数据部分
        return eth['src_mac'], ip['src_ip'], udp['src_port'], tftp_data

    def create_ethernet_frame(self, payload):
        """创建以太网帧"""
        # 使用接收到的源MAC地址作为目标MAC
        dst_mac = bytes.fromhex(self.last_src_mac.replace(':', ''))
        src_mac = bytes.fromhex(self.src_mac.replace(':', ''))
        return Protocol.ETH_HEADER.pack(dst_mac, src_mac, 0x0800) + payload

    def create_ip_packet(self, payload):
        """创建IP数据包"""
        version_ihl = 0x45
        dscp_ecn = 0
        total_length = 20 + 8 + len(payload)  # IP头 + UDP头 + 数据
        identification = 54321
        flags_frag = 0
        ttl = 64
        protocol = 17  # UDP
        checksum = 0
        src_ip = socket.inet_aton(self.src_ip)
        dst_ip = socket.inet_aton(self.last_src_ip)  # 使用接收到的源IP作为目标IP
        
        ip_header = Protocol.IP_HEADER.pack(
            version_ihl, dscp_ecn, total_length,
            identification, flags_frag, ttl,
            protocol, checksum, src_ip, dst_ip
        )
        return ip_header + payload

    def create_udp_packet(self, payload, dst_port):
        """创建UDP数据包"""
        length = 8 + len(payload)  # UDP头 + 数据
        checksum = 0
        return Protocol.UDP_HEADER.pack(self.src_port, dst_port, length, checksum) + payload

    def send_response(self, tftp_payload, dst_port):
        """
        发送完整协议栈的响应数据
        :param tftp_payload: TFTP协议数据
        :param dst_port: 目标端口
        """
        udp_packet = self.create_udp_packet(tftp_payload, dst_port)
        ip_packet = self.create_ip_packet(udp_packet)
        eth_frame = self.create_ethernet_frame(ip_packet)
        
        self.sock.sendall(eth_frame)
        print(f"\n[{datetime.now()}] 发送响应 ({len(eth_frame)} 字节)")
        HexPrinter.print_hex(eth_frame)

    def handle_rrq(self, src_mac, src_ip, src_port, filename, options=None):
        """
        处理读取请求(RRQ)
        :param options: 选项字典 (如 {'blksize': '1024'})
        """
        options = options or {}
        filepath = os.path.join(self.base_dir, filename)
        print(f"[{datetime.now()}] RRQ 请求文件: {filepath} (选项: {options})")
        
        if not os.path.exists(filepath):
            error_msg = f"文件未找到: {filename}"
            print(f"[{datetime.now()}] {error_msg}")
            error_packet = self._create_error_packet(1, error_msg)
            self.send_response(error_packet, src_port)
            return
        
        # 处理选项
        block_size = self._parse_block_size(options.get('blksize'))
        
        # 记录传输会话
        self.transfers[src_port] = {
            'filename': filename,
            'block_num': 0,  # 初始化为0，等待ACK 0
            'mode': 'octet',
            'type': 'read',
            'client_port': src_port,
            'file': open(filepath, 'rb'),
            'block_size': block_size,
            'options': options,
            'waiting_for_ack0': True  # 标记正在等待ACK 0
        }
        
        # 如果有选项，发送OACK响应
        if options:
            oack_packet = self._create_oack_packet(options)
            self.send_response(oack_packet, src_port)
        else:
            # 没有选项则直接发送第一个数据块
            self._send_next_data_block(src_port)

    def handle_wrq(self, src_mac, src_ip, src_port, filename, options=None):
        """
        处理写入请求(WRQ)
        :param options: 选项字典 (如 {'blksize': '1024'})
        """
        options = options or {}
        filepath = os.path.join(self.base_dir, filename)
        print(f"[{datetime.now()}] WRQ 请求上传文件: {filepath} (选项: {options})")
        
        # 检查文件是否已存在，存在则删除
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                print(f"[{datetime.now()}] 已删除已存在的文件: {filename}")
            except Exception as e:
                error_msg = f"无法删除旧文件: {str(e)}"
                print(f"[{datetime.now()}] {error_msg}")
                error_packet = self._create_error_packet(2, error_msg)
                self.send_response(error_packet, src_port)
                return
        
        try:
            # 处理选项
            block_size = self._parse_block_size(options.get('blksize'))
            
            # 记录传输会话
            self.transfers[src_port] = {
                'filename': filename,
                'block_num': 0,  # 初始块号为0
                'mode': 'octet',
                'type': 'write',
                'client_port': src_port,
                'file': open(filepath, 'wb'),
                'block_size': block_size,
                'options': options,
                'waiting_for_ack0': bool(options)  # 如果有选项则等待ACK 0
            }
            
            # 如果有选项，发送OACK响应
            if options:
                oack_packet = self._create_oack_packet(options)
                self.send_response(oack_packet, src_port)
            else:
                # 没有选项则直接发送ACK 0
                ack_packet = self._create_ack_packet(0)
                self.send_response(ack_packet, src_port)
                self.transfers[src_port]['waiting_for_ack0'] = False
                
        except Exception as e:
            error_msg = f"无法创建文件: {str(e)}"
            print(f"[{datetime.now()}] {error_msg}")
            error_packet = self._create_error_packet(0, error_msg)
            self.send_response(error_packet, src_port)
            if src_port in self.transfers:
                del self.transfers[src_port]
    
    def _parse_block_size(self, blksize_str):
        """解析块大小选项"""
        try:
            blksize = int(blksize_str) if blksize_str else self.default_block_size
            return min(max(blksize, 8), 65464)  # RFC 2348限制
        except ValueError:
            return self.default_block_size
        
    def _create_oack_packet(self, options):
        """创建OACK数据包"""
        parts = []
        for key, value in options.items():
            parts.append(key.encode('ascii'))
            parts.append(str(value).encode('ascii'))
        return struct.pack('!H', Protocol.TFTP_OP_OACK) + b'\x00'.join(parts) + b'\x00'
        
    def handle_data(self, src_port, block_num, data):
        """
        处理数据包(DATA) - 用于文件上传
        :param src_port: 客户端端口
        :param block_num: 数据块号
        :param data: 接收到的数据
        """
        if src_port not in self.transfers:
            print(f"[{datetime.now()}] 收到未知端口的数据包: {src_port}")
            return
            
        transfer = self.transfers[src_port]
        
        if transfer['type'] != 'write':
            print(f"[{datetime.now()}] 收到非写入传输的数据包")
            return
            
        # 检查块号是否连续
        expected_block = transfer['block_num'] + 1
        if block_num != expected_block:
            print(f"[{datetime.now()}] 数据块号不连续: 收到 {block_num}, 期望 {expected_block}")
            return
            
        try:
            # 写入数据到文件
            transfer['file'].write(data)
            transfer['block_num'] = block_num  # 更新当前块号
            
            # 发送ACK确认
            ack_packet = self._create_ack_packet(block_num)
            self.send_response(ack_packet, src_port)
            
            # 检查是否是最后一个数据包(小于512字节表示结束)
            if len(data) < 512:
                print(f"[{datetime.now()}] 文件上传完成: {transfer['filename']}")
                transfer['file'].close()
                del self.transfers[src_port]
                
        except Exception as e:
            error_msg = f"写入文件错误: {str(e)}"
            print(f"[{datetime.now()}] {error_msg}")
            error_packet = self._create_error_packet(0, error_msg)
            self.send_response(error_packet, src_port)
            transfer['file'].close()
            del self.transfers[src_port]

    def handle_ack(self, src_port, block_num):
        """
        处理ACK确认 - 用于文件下载
        :param src_port: 客户端端口
        :param block_num: 确认的块号
        """
        if src_port not in self.transfers:
            print(f"[{datetime.now()}] 收到未知端口的ACK: {src_port}")
            return
            
        transfer = self.transfers[src_port]
        
        if transfer['type'] != 'read':
            print(f"[{datetime.now()}] 收到非读取传输的ACK")
            return
        
        # 检查是否在等待ACK 0
        if transfer.get('waiting_for_ack0', False):
            if block_num == 0:
                print(f"[{datetime.now()}] 收到OACK的ACK 0确认，开始传输数据")
                transfer['waiting_for_ack0'] = False
                transfer['block_num'] = 1  # 从块1开始传输
                self._send_next_data_block(src_port)
            else:
                print(f"[{datetime.now()}] 期望ACK 0但收到ACK {block_num}")
            return
        
        # 正常ACK处理
        # 期望的块号应该是当前block_num - 1，因为ACK确认的是已经发送的块
        expected_block = transfer['block_num'] - 1
        if block_num != expected_block:
            print(f"[{datetime.now()}] ACK块号不匹配: 收到 {block_num}, 期望 {expected_block}")
            return
            
        # 发送下一个数据块
        self._send_next_data_block(src_port)

    def _send_next_data_block(self, src_port):
        """发送下一个数据块(用于下载)"""
        transfer = self.transfers[src_port]
        block_size = transfer.get('block_size', self.default_block_size)
        
        # 读取下一个数据块
        data = transfer['file'].read(block_size)
        
        if not data:  # 文件传输完成
            print(f"[{datetime.now()}] 文件传输完成: {transfer['filename']}")
            transfer['file'].close()
            del self.transfers[src_port]
            return
            
        # 发送数据包并更新块号
        data_packet = self._create_data_packet(transfer['block_num'], data)
        self.send_response(data_packet, src_port)
        transfer['block_num'] += 1

    def _create_data_packet(self, block_num, data):
        """创建DATA数据包"""
        return struct.pack('!HH', Protocol.TFTP_OP_DATA, block_num) + data

    def _create_ack_packet(self, block_num):
        """创建ACK数据包"""
        return struct.pack('!HH', Protocol.TFTP_OP_ACK, block_num)

    def _create_error_packet(self, error_code, error_msg):
        """创建ERROR数据包"""
        return struct.pack('!HH', Protocol.TFTP_OP_ERROR, error_code) + error_msg.encode('ascii') + b'\x00'

    def run(self):
        """运行TFTP服务器主循环"""
        self.connect_to_bridge()
        print(f"[{datetime.now()}] TFTP Server 准备接收请求...")

        try:
            while True:
                data = self.sock.recv(2048)
                if not data:
                    break

                # 解析网络数据包
                src_mac, src_ip, src_port, tftp_data = self.parse_packet(data)
                if not tftp_data:
                    continue
                    
                # 解析TFTP协议
                tftp = self.parser.parse_tftp_packet(tftp_data)
                if not tftp:
                    continue

                self.parser.print_tftp_packet(tftp, tftp_data)  # 打印TFTP包信息
                    
                print(f"[{datetime.now()}] 收到 TFTP 请求 (Opcode={tftp['opcode']})")

                # 根据操作码分发处理
                if tftp['opcode'] == Protocol.TFTP_OP_RRQ:
                    self.handle_rrq(src_mac, src_ip, src_port, tftp['filename'], tftp['options'])
                elif tftp['opcode'] == Protocol.TFTP_OP_WRQ:
                    self.handle_wrq(src_mac, src_ip, src_port, tftp['filename'])
                elif tftp['opcode'] == Protocol.TFTP_OP_DATA:
                    self.handle_data(src_port, tftp['block_num'], tftp['data'])
                elif tftp['opcode'] == Protocol.TFTP_OP_ACK:
                    self.handle_ack(src_port, tftp['block_num'])
                else:
                    print(f"[{datetime.now()}] 不支持的操作码: {tftp['opcode']}")

        except KeyboardInterrupt:
            print("\n服务器正在关闭...")
        except Exception as e:
            print(f"[{datetime.now()}] 错误: {e}")
        finally:
            # 清理所有打开的文件
            for transfer in self.transfers.values():
                if 'file' in transfer:
                    transfer['file'].close()
            if self.sock:
                self.sock.close()
            print(f"[{datetime.now()}] TFTP Server 已关闭")

def main():
    server = TFTPServer('127.0.0.1', 1069)
    server.run()

if __name__ == "__main__":
    main()