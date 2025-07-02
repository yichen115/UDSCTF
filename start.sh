#!/bin/bash

# 启动脚本 - 设置环境并启动UDSCTF挑战

echo "正在启动UDSCTF挑战环境..."

# 执行安全清理
/usr/local/bin/cleanup.sh

# 设置用户权限
/usr/local/bin/setup_permissions.sh

# 加载CAN模块
modprobe can
modprobe can_raw
modprobe vcan

# 创建虚拟CAN接口
ip link add dev vcan0 type vcan
ip link set up vcan0

echo "CAN接口vcan0已创建并启动"

# 切换到系统目录启动UDS服务器（选手无法访问）
cd /opt/udsctf

# 清理任何可能的源代码文件（双重安全措施）
find /home/ctfuser -name "*.c" -delete 2>/dev/null || true
find /home/ctfuser -name "*.h" -delete 2>/dev/null || true
find /home/ctfuser -name "Makefile" -delete 2>/dev/null || true
find /home/ctfuser -name "*.o" -delete 2>/dev/null || true
find /home/ctfuser -name "*.py" -delete 2>/dev/null || true

# 后台启动UDS服务器（从系统目录）
./uds_server &
UDS_PID=$!

echo "UDS服务器已启动 (PID: $UDS_PID)"

# 生成SSH主机密钥（如果不存在）
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi

# 启动SSH服务
echo "启动SSH服务..."
/usr/sbin/sshd -D 