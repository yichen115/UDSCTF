#!/bin/bash
# 安全清理脚本 - 删除源代码文件并设置安全环境

echo "执行安全清理..."

# 删除所有源代码文件
echo "删除源代码文件..."
find /home/ctfuser -name "*.c" -delete 2>/dev/null || true
find /home/ctfuser -name "*.h" -delete 2>/dev/null || true
find /home/ctfuser -name "Makefile" -delete 2>/dev/null || true
find /home/ctfuser -name "*.o" -delete 2>/dev/null || true
find /home/ctfuser -name "*.py" -delete 2>/dev/null || true

# 删除编译工具（可选，增加安全性）
echo "删除编译工具..."
apt-get remove -y build-essential gcc g++ make 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

# 清理包缓存
echo "清理包缓存..."
apt-get clean 2>/dev/null || true

# 设置UDS服务器文件权限（只允许root访问）
echo "设置UDS服务器权限..."
chmod 700 /opt/udsctf/uds_server 2>/dev/null || true
chown root:root /opt/udsctf/uds_server 2>/dev/null || true

# 设置工作目录权限
echo "设置工作目录权限..."
chown ctfuser:ctfuser /home/ctfuser/challenge 2>/dev/null || true
chmod 755 /home/ctfuser/challenge 2>/dev/null || true

# 创建只读文件系统（可选，增加安全性）
# mount -o remount,ro /opt/udsctf 2>/dev/null || true

echo "安全清理完成" 