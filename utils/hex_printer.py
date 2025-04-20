class HexPrinter:
    """增强版十六进制数据打印工具，支持类似Wireshark的显示风格"""
    
    @staticmethod
    def print_hex(data, prefix=''):
        """
        格式化打印二进制数据
        :param data: 要打印的二进制数据
        :param prefix: 每行前缀字符串 (用于缩进)
        """
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            # 1. 打印偏移量 (8位十六进制)
            offset = f"{i:08x}"
            
            # 2. 生成十六进制部分 (每8字节为一组)
            hex_parts = []
            for j in range(0, len(chunk), 8):
                sub_chunk = chunk[j:j+8]
                hex_str = ' '.join(f"{b:02x}" for b in sub_chunk)
                hex_parts.append(hex_str.ljust(23))  # 保持对齐
            
            # 3. 生成ASCII可打印部分
            ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            # 4. 组合输出
            print(f"{prefix}{offset}  {'  '.join(hex_parts).ljust(47)}  |{ascii_line}|")