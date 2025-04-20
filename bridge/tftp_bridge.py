from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Thread, Lock
from typing import Dict, Optional, Tuple
import sys
from pathlib import Path
# 将utils目录添加到Python路径
utils_path = Path(__file__).parent.parent / 'utils'
sys.path.append(str(utils_path))

from protocol import Protocol
from packet_parser import PacketParser
from hex_printer import HexPrinter

class TCPServer:
    """TCP 服务器（通过客户端端口区分连接）"""

    def __init__(self, listen_port: int, parser: Optional[object] = None):
        """
        Args:
            listen_port: 服务器监听端口
            parser: 可选协议解析器（需实现 parse(data) 方法）
        """
        self.listen_port = listen_port
        self.parser = parser
        self.client_sockets: Dict[int, socket] = {}  # {client_port: socket}
        self.lock = Lock()
        self.running = False
        self.server_sock = None

    def _broadcast(self, src_port: int, data: bytes):
        """将数据广播给其他所有客户端"""
        with self.lock:
            for dst_port, dst_sock in self.client_sockets.items():
                if dst_port != src_port:  # 不发给发送者自己
                    try:
                        dst_sock.sendall(data)
                        print(f"转发: [客户端 {src_port} → 客户端 {dst_port}] 数据长度: {len(data)} bytes")
                    except ConnectionError:
                        del self.client_sockets[dst_port]

    def _handle_client(self, client_sock: socket, client_addr: Tuple[str, int]):
        """处理单个客户端连接"""
        _, client_port = client_addr
        with self.lock:
            self.client_sockets[client_port] = client_sock
        print(f"新客户端连接: 端口 {client_port}")

        try:
            while self.running:
                data = client_sock.recv(4096)
                if not data:
                    break
                
                # 调用解析器（如果存在）
                if self.parser and hasattr(self.parser, 'parse'):
                    self.parser.parse(data)
                
                # 广播数据
                self._broadcast(client_port, data)
        except ConnectionResetError:
            print(f"客户端 {client_port} 异常断开")
        finally:
            with self.lock:
                if client_port in self.client_sockets:
                    del self.client_sockets[client_port]
            client_sock.close()
            print(f"客户端断开: 端口 {client_port}")

    def start(self):
        """启动服务器"""
        self.running = True
        self.server_sock = socket(AF_INET, SOCK_STREAM)
        self.server_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)  # 设置端口重用
        
        try:
            self.server_sock.bind(('0.0.0.0', self.listen_port))
            self.server_sock.listen(5)
            print(f"服务器启动，监听端口 {self.listen_port}")

            while self.running:
                try:
                    client_sock, client_addr = self.server_sock.accept()
                    Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True).start()
                except OSError as e:
                    if self.running:  # 如果不是因为关闭导致的错误
                        print(f"接受连接时出错: {e}")
                    break
        except Exception as e:
            print(f"服务器启动失败: {e}")
            self.running = False
        finally:
            self.stop()

    def stop(self):
        """停止服务器"""
        if not self.running:
            return
            
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception as e:
                print(f"关闭服务器套接字时出错: {e}")
        
        with self.lock:
            for port, sock in list(self.client_sockets.items()):
                try:
                    sock.close()
                    del self.client_sockets[port]
                except Exception as e:
                    print(f"关闭客户端 {port} 套接字时出错: {e}")
        print("服务器已关闭")

class ParserDump:
    """协议解析和打印的封装类"""
    
    @staticmethod
    def parse(data):
        """解析并打印TFTP数据包"""
        # 先解析TFTP数据包
        # HexPrinter.print_hex(data)  # 打印原始数据
        # packet = PacketParser.parse_tftp_packet(data[14+20+8:])
        # # HexPrinter.print_hex(packet)  # 再打印原始数据
        # # 然后打印解析结果
        # PacketParser.print_tftp_packet(packet, data)
        # return packet  # 可选返回解析结果
    
if __name__ == "__main__":
    try:
        # 创建TFTP解析器实例
        parser = ParserDump()
        server = TCPServer(listen_port=1069, parser=parser)
        server.start()
    except KeyboardInterrupt:
        print("\n接收到中断信号，正在关闭服务器...")
    except Exception as e:
        print(f"服务器运行出错: {e}")