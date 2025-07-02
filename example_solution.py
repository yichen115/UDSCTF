#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDSCTF 挑战解题示例
这个脚本演示了如何通过UDS协议获取flag
"""

import can
import struct
import time

def solve_udsctf():
    """解决UDSCTF挑战"""
    print("UDSCTF 解题脚本")
    print("===============")
    
    # 连接到CAN总线
    try:
        bus = can.interface.Bus(channel='vcan0', interface='socketcan')
        print("✓ 已连接到CAN总线 vcan0")
    except Exception as e:
        print(f"❌ 连接CAN总线失败: {e}")
        return
    
    try:
        # 步骤1: 诊断会话控制 (0x10 01)
        print("\n步骤1: 发送诊断会话控制请求...")
        msg = can.Message(arbitration_id=0x7E0, data=[0x02, 0x10, 0x01], is_extended_id=False)
        bus.send(msg)
        print(f"发送: 0x{msg.arbitration_id:03X} {msg.data.hex().upper()}")
        
        # 等待响应
        response = bus.recv(timeout=2.0)
        if response and response.arbitration_id == 0x7E8:
            print(f"接收: 0x{response.arbitration_id:03X} {response.data.hex().upper()}")
            if response.data[1] == 0x50:
                print("✓ 诊断会话建立成功")
            else:
                print("❌ 诊断会话建立失败")
                return
        else:
            print("❌ 未收到响应")
            return
        
        # 步骤2: 安全访问 - 请求种子 (0x27 01)
        print("\n步骤2: 请求安全访问种子...")
        msg = can.Message(arbitration_id=0x7E0, data=[0x02, 0x27, 0x01], is_extended_id=False)
        bus.send(msg)
        print(f"发送: 0x{msg.arbitration_id:03X} {msg.data.hex().upper()}")
        
        response = bus.recv(timeout=2.0)
        if response and response.arbitration_id == 0x7E8:
            print(f"接收: 0x{response.arbitration_id:03X} {response.data.hex().upper()}")
            if response.data[1] == 0x67:
                # 提取种子
                seed = struct.unpack('>I', response.data[2:6])[0]
                print(f"✓ 获取种子: 0x{seed:08X}")
            else:
                print("❌ 获取种子失败")
                return
        else:
            print("❌ 未收到响应")
            return
        
        # 步骤3: 安全访问 - 发送密钥 (0x27 02)
        print("\n步骤3: 计算并发送密钥...")
        key = seed ^ 0xdeadbeef  # 从源码分析得出的算法
        key_bytes = struct.pack('>I', key)
        print(f"计算密钥: 0x{seed:08X} ^ 0xDEADBEEF = 0x{key:08X}")
        
        msg = can.Message(arbitration_id=0x7E0, 
                        data=[0x06, 0x27, 0x02] + list(key_bytes), 
                        is_extended_id=False)
        bus.send(msg)
        print(f"发送: 0x{msg.arbitration_id:03X} {msg.data.hex().upper()}")
        
        response = bus.recv(timeout=2.0)
        if response and response.arbitration_id == 0x7E8:
            print(f"接收: 0x{response.arbitration_id:03X} {response.data.hex().upper()}")
            if response.data[1] == 0x67:
                print("✓ 安全访问解锁成功")
            else:
                print("❌ 密钥验证失败")
                return
        else:
            print("❌ 未收到响应")
            return
        
        # 步骤4: 读取VIN数据 (0x22 F190)
        print("\n步骤4: 读取VIN数据...")
        msg = can.Message(arbitration_id=0x7E0, 
                        data=[0x03, 0x22, 0xF1, 0x90], 
                        is_extended_id=False)
        bus.send(msg)
        print(f"发送: 0x{msg.arbitration_id:03X} {msg.data.hex().upper()}")
        
        # 处理ISO-TP多帧响应
        all_data = b""
        total_len = 0
        
        while True:
            response = bus.recv(timeout=2.0)
            if response and response.arbitration_id == 0x7E8:
                print(f"接收: 0x{response.arbitration_id:03X} {response.data.hex().upper()}")
                
                pci = response.data[0]
                
                if pci & 0xF0 == 0x10:  # 首帧 (First Frame)
                    total_len = ((pci & 0x0F) << 8) | response.data[1]
                    all_data = response.data[2:]
                    print(f"收到首帧，总长度: {total_len}")
                    
                    # 发送流控帧 (Flow Control)
                    fc_msg = can.Message(arbitration_id=0x7E0, 
                                       data=[0x30, 0x00, 0x00], 
                                       is_extended_id=False)
                    bus.send(fc_msg)
                    print(f"发送FC: 0x{fc_msg.arbitration_id:03X} {fc_msg.data.hex().upper()}")
                    
                elif pci & 0xF0 == 0x20:  # 连续帧 (Consecutive Frame)
                    sn = pci & 0x0F
                    all_data += response.data[1:]
                    print(f"收到连续帧 SN={sn}")
                    
                elif pci & 0xF0 == 0x00:  # 单帧 (Single Frame)
                    data_len = pci & 0x0F
                    all_data = response.data[1:1+data_len]
                    break
                    
                # 检查是否收完
                if len(all_data) >= total_len:
                    all_data = all_data[:total_len]
                    break
            else:
                print("❌ 接收超时")
                break
        
        # 解析数据
        if len(all_data) >= 3 and all_data[0] == 0x62:  # 正响应
            did = struct.unpack('>H', all_data[1:3])[0]
            vin_data = all_data[3:]
            
            print(f"✓ 响应SID: 0x{all_data[0]:02X}")
            print(f"✓ DID: 0x{did:04X}")
            print(f"✓ VIN数据: {vin_data}")
            
            # 尝试解码为字符串
            try:
                vin_str = vin_data.decode('utf-8')
                print(f"✓ VIN字符串: {vin_str}")
                
                if "CTF{" in vin_str:
                    print(f"\n🎉 找到Flag: {vin_str}")
                else:
                    print("❌ 数据中未找到flag")
                    
            except UnicodeDecodeError:
                print(f"❌ VIN数据无法解码为UTF-8: {vin_data.hex()}")
        else:
            print(f"❌ 响应格式错误: {all_data.hex()}")
    
    except Exception as e:
        print(f"❌ 执行过程中出现错误: {e}")
    
    finally:
        bus.shutdown()
        print("\n解题完成")

if __name__ == "__main__":
    solve_udsctf() 