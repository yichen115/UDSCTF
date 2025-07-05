#!/bin/bash
# 权限设置脚本 - 在容器启动时设置用户权限

echo "设置用户权限限制..."

# 确保用户目录权限正确
chown ctfuser:ctfuser /home/ctfuser/challenge
chmod 755 /home/ctfuser/challenge

# 限制用户访问系统目录
chmod 750 /home/ctfuser

# 确保可执行文件权限
chmod 700 /opt/udsctf/uds_server
chown root:root /opt/udsctf/uds_server

# 创建欢迎信息文件
cat > /home/ctfuser/.welcome << 'EOF'
欢迎来到UDSCTF挑战环境！

可用工具：
- python3: 使用python-can、isotp库
- vim: 编辑Python脚本
- cansend: 发送CAN帧
- candump: 监听CAN帧
- cangen: 生成CAN帧
- isotpdump: ISO-TP协议监听
- isotpsend: ISO-TP协议发送

CAN接口: vcan0
UDS服务监听: 0x7E0
UDS响应: 0x7E8

提示: 使用vim编辑Python脚本进行UDS协议探索
EOF

chown ctfuser:ctfuser /home/ctfuser/.welcome

# 确保.bashrc权限正确
chown ctfuser:ctfuser /home/ctfuser/.bashrc

echo "权限设置完成" 