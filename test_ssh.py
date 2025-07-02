#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH连接测试脚本 - UDSCTF挑战

测试SSH连接和基本功能
"""

import paramiko
import time
import sys

def test_ssh_connection(host='localhost', port=2222, username='ctfuser', password='ctfpassword'):
    """测试SSH连接"""
    print(f"🔗 测试SSH连接到 {host}:{port}")
    
    try:
        # 创建SSH客户端
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 连接
        ssh.connect(host, port=port, username=username, password=password, timeout=10)
        print("✅ SSH连接成功")
        
        # 获取shell
        shell = ssh.invoke_shell()
        time.sleep(2)
        
        # 读取欢迎信息
        output = shell.recv(4096).decode('utf-8')
        print("📋 欢迎信息:")
        print(output)
        
        # 测试基本命令
        print("\n🧪 测试基本命令...")
        
        # 测试pwd命令
        shell.send(b'pwd\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("📁 当前目录:")
        print(output)
        
        # 测试ls命令
        shell.send(b'ls -la\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("📁 目录内容:")
        print(output)
        
        # 测试python3
        shell.send(b'python3 --version\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("🐍 Python版本:")
        print(output)
        
        # 测试CAN接口
        shell.send(b'ip link show vcan0\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("🔌 CAN接口状态:")
        print(output)
        
        # 测试编辑器
        print("\n📝 测试编辑器...")
        shell.send(b'vim --version | head -1\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("📝 vim版本:")
        print(output)
        
        # 测试用户权限
        print("\n👤 测试用户权限...")
        shell.send(b'whoami\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("👤 用户信息:")
        print(output)
        
        # 测试基本文件操作
        print("\n📝 测试文件操作...")
        shell.send(b'echo "print(\'Hello UDSCTF\')" > test.py\n')
        time.sleep(1)
        shell.send(b'cat test.py\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("📄 文件内容:")
        print(output)
        
        # 测试Python执行
        shell.send(b'python3 test.py\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("🐍 Python执行:")
        print(output)
        
        # 测试受限命令
        print("\n🚫 测试受限命令...")
        shell.send(b'find /etc\n')
        time.sleep(1)
        output = shell.recv(4096).decode('utf-8')
        print("🚫 find命令测试:")
        print(output)
        
        # 退出
        shell.send(b'exit\n')
        ssh.close()
        
        print("\n✅ 所有测试完成")
        
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        return False
    
    return True

def test_can_functionality():
    """测试CAN功能"""
    print("\n🔌 测试CAN功能...")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('localhost', port=2222, username='ctfuser', password='ctfpassword')
        
        # 测试python-can
        stdin, stdout, stderr = ssh.exec_command('python3 -c "import can; print(\'python-can available\')"')
        result = stdout.read().decode('utf-8').strip()
        print(f"🐍 python-can测试: {result}")
        
        # 测试can-utils
        stdin, stdout, stderr = ssh.exec_command('cansend --help')
        result = stdout.read().decode('utf-8')
        if 'Usage:' in result:
            print("✅ cansend可用")
        else:
            print("❌ cansend不可用")
        
        # 测试编辑器交互
        print("\n📝 测试编辑器交互...")
        stdin, stdout, stderr = ssh.exec_command('echo "print(\'test\')" | python3')
        result = stdout.read().decode('utf-8').strip()
        print(f"🐍 简单Python执行: {result}")
        
        ssh.close()
        
    except Exception as e:
        print(f"❌ CAN功能测试失败: {e}")

if __name__ == "__main__":
    print("🚀 UDSCTF SSH连接测试")
    print("=" * 50)
    
    # 测试SSH连接
    if test_ssh_connection():
        # 测试CAN功能
        test_can_functionality()
        
        print("\n🎉 测试完成！")
        print("\n📋 连接信息:")
        print("   SSH: ssh ctfuser@localhost -p 2222")
        print("   密码: ctfpassword")
        print("\n💡 提示:")
        print("   - 使用vim编辑Python脚本")
        print("   - 使用python-can库与CAN总线交互")
        print("   - 探索UDS协议获取flag")
        print("   - 现在支持完整的交互式编辑")
        print("   - 基本命令在题目目录内正常使用")
    else:
        print("\n❌ 测试失败，请检查:")
        print("   1. 容器是否正在运行")
        print("   2. 端口2222是否开放")
        print("   3. SSH服务是否正常")
        sys.exit(1) 