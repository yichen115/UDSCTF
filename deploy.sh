#!/bin/bash
# UDSCTF 挑战一键部署脚本

set -e

echo "🚗 UDSCTF 部署脚本启动..."
echo "================================"

# 检查Docker是否安装
if ! command -v docker &> /dev/null; then
    echo "❌ 错误: Docker未安装，请先安装Docker"
    exit 1
fi

# 检查是否有docker-compose
if command -v docker-compose &> /dev/null; then
    echo "✅ 检测到docker-compose，使用docker-compose部署"
    DEPLOY_METHOD="docker-compose"
else
    echo "⚠️  未检测到docker-compose，使用Docker直接部署"
    DEPLOY_METHOD="docker"
fi

# 检查当前用户是否有Docker权限
if ! docker info &> /dev/null; then
    echo "错误: 当前用户没有Docker权限，请添加到docker组或使用sudo"
    exit 1
fi

if [ "$DEPLOY_METHOD" = "docker-compose" ]; then
    echo "📦 使用docker-compose构建并启动服务..."
    docker-compose up -d --build
    
    echo "✅ 部署完成！"
    echo ""
    echo "📋 连接信息："
    echo "   SSH连接: ssh ctfuser@localhost -p 2222"
    echo "   密码: ctfpassword"
    echo ""
    echo "🔧 管理命令："
    echo "   查看日志: docker-compose logs -f"
    echo "   停止服务: docker-compose down"
    echo "   重启服务: docker-compose restart"
    
else
    echo "🔨 构建Docker镜像..."
    docker build -t udsctf:latest .
    
    echo "🐳 使用Docker直接启动容器..."
    
    # 停止并删除旧容器（如果存在）
    docker stop udsctf-container 2>/dev/null || true
    docker rm udsctf-container 2>/dev/null || true
    
    # 启动新容器
    docker run -d \
        --name udsctf-container \
        --privileged \
        -p 2222:22 \
        --restart unless-stopped \
        udsctf:latest
    
    echo "✅ 部署完成！"
    echo ""
    echo "📋 连接信息："
    echo "   SSH连接: ssh ctfuser@localhost -p 2222"
    echo "   密码: ctfpassword"
    echo ""
    echo "🔧 管理命令："
    echo "   查看日志: docker logs -f udsctf-container"
    echo "   停止服务: docker stop udsctf-container"
    echo "   重启服务: docker restart udsctf-container"
    echo "   删除容器: docker rm -f udsctf-container"
fi

echo ""
echo "🎯 挑战说明："
echo "   1. 通过SSH连接到环境"
echo "   2. 使用python-can库与CAN总线交互"
echo "   3. 探索UDS协议获取flag"
echo "   4. 可用工具: nano, vim, cansend, candump等"
echo ""
echo "🔒 安全措施："
echo "   - 源代码和可执行文件已保护"
echo "   - 受限shell限制命令执行"
echo "   - 文件访问权限严格控制"

echo ""
echo "挑战环境已部署！🎉"
echo "===================="