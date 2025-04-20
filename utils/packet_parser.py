from protocol import Protocol
from hex_printer import HexPrinter
import struct

class PacketParser(Protocol):
    """网络数据包解析工具 (继承自Protocol类获取常量)"""
    
    @staticmethod
    def parse_ethernet_frame(data):
        """解析以太网帧"""
        if len(data) < 14:
            return None
        
        try:
            # 确保使用大端字节序解析以太网头部
            dst_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
            return {
                'src_mac': Protocol.mac_to_str(src_mac),
                'dst_mac': Protocol.mac_to_str(dst_mac),
                'ethertype': ethertype
            }
        except struct.error:
            return None

    @staticmethod
    def parse_ip_packet(data):
        """解析IP数据包"""
        if len(data) < 20:
            return None
            
        try:
            # 确保使用大端字节序解析IP头部
            ver_ihl, _, total_len, _, _, _, proto, _, src_ip, dst_ip = \
                struct.unpack('!BBHHHBBH4s4s', data[:20])
            return {
                'total_length': total_len,
                'protocol': proto,
                'src_ip': Protocol.ip_to_str(src_ip),
                'dst_ip': Protocol.ip_to_str(dst_ip),
                'version': ver_ihl >> 4
            }
        except struct.error:
            return None

    @staticmethod
    def parse_udp_packet(data):
        """解析UDP数据包"""
        if len(data) < 8:
            return None
            
        try:
            # 确保使用大端字节序解析UDP头部
            src_port, dst_port, length, _ = struct.unpack('!HHHH', data[:8])
            return {
                'src_port': src_port,
                'dst_port': dst_port,
                'length': length
            }
        except struct.error:
            return None

    @staticmethod
    def parse_tftp_packet(data):
        """解析TFTP协议数据"""
        if len(data) < 2:
            return None
            
        try:
            opcode = struct.unpack('!H', data[:2])[0]
            result = {'opcode': opcode}
            
            if opcode in (Protocol.TFTP_OP_RRQ, Protocol.TFTP_OP_WRQ):
                parts = data[2:].split(b'\x00')
                if len(parts) >= 2:
                    result.update({
                        'filename': parts[0].decode('ascii'),
                        'mode': parts[1].decode('ascii')
                    })
                    # 解析选项
                    if len(parts) > 2:
                        options = {}
                        remaining = parts[2:-1]  # 去掉最后的空字符串
                        for i in range(0, len(remaining), 2):
                            if i+1 < len(remaining):
                                options[remaining[i].decode('ascii')] = remaining[i+1].decode('ascii')
                        result['options'] = options
                        
            elif opcode == Protocol.TFTP_OP_OACK:
                parts = data[2:].split(b'\x00')[:-1]  # 去掉最后的空字符串
                options = {}
                for i in range(0, len(parts), 2):
                    if i+1 < len(parts):
                        options[parts[i].decode('ascii')] = parts[i+1].decode('ascii')
                result['options'] = options
                
            elif opcode == Protocol.TFTP_OP_DATA:
                result['block_num'] = struct.unpack('!H', data[2:4])[0]
                result['data'] = data[4:]
                
            elif opcode == Protocol.TFTP_OP_ACK:
                result['block_num'] = struct.unpack('!H', data[2:4])[0]
                
            elif opcode == Protocol.TFTP_OP_ERROR:
                result['error_code'] = struct.unpack('!H', data[2:4])[0]
                result['error_msg'] = data[4:].split(b'\x00', 1)[0].decode('ascii')
                
            return result
        except (struct.error, UnicodeDecodeError) as e:
            print(f"[解析错误] TFTP包解析失败: {e}")
            return None

    @staticmethod
    def print_tftp_packet(packet_info, data=None):
        """打印TFTP数据包信息"""
        if not packet_info:
            print("无效的TFTP数据包")
            return
            
        opcode = packet_info.get('opcode')
        op_name = Protocol.TFTP_OP_NAMES.get(opcode, '未知')
        print(f"\n[TFTP] 操作码({opcode}): {op_name}")
        
        if opcode in (Protocol.TFTP_OP_RRQ, Protocol.TFTP_OP_WRQ):
            print(f"  文件名: {packet_info.get('filename', '未知')}")
            print(f"  模式: {packet_info.get('mode', '未知')}")
            if 'options' in packet_info:
                print("  选项:")
                for k, v in packet_info['options'].items():
                    print(f"    {k}: {v}")
                    
        elif opcode == Protocol.TFTP_OP_OACK:
            print("  选项确认:")
            for k, v in packet_info.get('options', {}).items():
                print(f"    {k}: {v}")
                
        elif opcode == Protocol.TFTP_OP_DATA:
            print(f"  块编号: {packet_info.get('block_num', '未知')}")
            if data and len(data) > 4:
                print("  数据:")
                HexPrinter.print_hex(data[4:])
                
        elif opcode == Protocol.TFTP_OP_ACK:
            print(f"  确认块编号: {packet_info.get('block_num', '未知')}")
            
        elif opcode == Protocol.TFTP_OP_ERROR:
            print(f"  错误码: {packet_info.get('error_code', '未知')}")
            print(f"  错误信息: {packet_info.get('error_msg', '未知')}")