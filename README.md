# UDSCTF 挑战环境

基于ISO14229 UDS协议的CTF挑战环境，选手通过SSH连接后使用python-can或can-utils与CAN总线交互，探索UDS协议获取flag。

## 🚀 快速部署

### 方式一：使用部署脚本（推荐）
```bash
chmod +x deploy.sh
./deploy.sh
```

### 方式二：使用docker-compose
```bash
docker-compose up -d
```

### 方式三：手动Docker部署
```bash
docker build -t udsctf:latest .
docker run -d --name udsctf-container --privileged -p 2222:22 --restart unless-stopped udsctf:latest
```

## 🔗 连接方式

### SSH连接
```bash
ssh ctfuser@localhost -p 2222
# 密码: ctfpassword
```

连接后会自动进入bash shell环境，提供完整的交互式体验。

## 🛠️ 可用工具

### 编辑器
- **vim**: 高级文本编辑器，支持完整交互

### CAN总线工具
- **cansend**: 发送CAN帧
- **candump**: 监听CAN帧
- **cangen**: 生成CAN帧
- **isotpdump**: ISO-TP协议监听
- **isotpsend**: ISO-TP协议发送

### Python环境
- **python3**: 使用python-can库进行CAN总线编程

### 基本命令
- **ls, cat, grep**: 在题目目录内正常使用
- **pwd, cd, echo**: 基本文件操作
- **ps, ip, whoami**: 系统信息查看

## 📝 编辑器使用示例

### vim编辑器
```bash
# 创建并编辑Python脚本
vim exploit.py

# vim基本操作：
# i: 插入模式
# Esc: 命令模式
# :w: 保存文件
# :q: 退出
# :wq: 保存并退出
# /text: 搜索文本
# :s/old/new/g: 替换文本
```

## 🎯 挑战目标

1. 通过SSH连接到环境
2. 使用python-can库与CAN总线交互
3. 探索UDS协议，发现隐藏的服务
4. 获取flag

### CAN接口信息
- **接口**: vcan0
- **UDS请求ID**: 0x7E0
- **UDS响应ID**: 0x7E8

## 🔒 安全措施

### 权限控制
- 源代码和可执行文件已保护，选手无法访问
- 用户使用正常的bash shell，权限合理限制
- 文件访问权限严格控制

### 文件访问限制
- 禁止访问系统关键目录（/etc, /proc, /sys, /dev, /opt等）
- 禁止使用find命令
- 在题目目录内可以正常使用所有基本命令

### 目录权限
- 用户主要工作目录：`/home/ctfuser/challenge`
- 系统目录和可执行文件目录权限严格限制
- 源代码编译后立即删除

## 🐛 故障排除

### 连接问题
```bash
# 检查容器状态
docker ps | grep udsctf

# 查看容器日志
docker logs udsctf-container

# 重启容器
docker restart udsctf-container
```

### 权限问题
```bash
# 确保容器以privileged模式运行
docker run --privileged ...

# 检查CAN接口
ip link show vcan0
```

### 编辑器问题
```bash
# 设置正确的终端类型
export TERM=xterm

# 检查编辑器是否可用
which vim
```

### 交互式问题
```bash
# 确保使用SSH连接而不是nc
ssh ctfuser@localhost -p 2222

# 检查shell类型
echo $SHELL

# 测试编辑器交互
vim test.txt
```

## 📚 学习资源

### UDS协议
- [ISO14229标准](https://www.iso.org/standard/69583.html)
- [UDS协议详解](https://en.wikipedia.org/wiki/Unified_Diagnostic_Services)

### Python-CAN
- [python-can文档](https://python-can.readthedocs.io/)
- [CAN总线编程示例](https://github.com/hardbyte/python-can/tree/master/examples)

### CAN工具
- [can-utils文档](https://github.com/linux-can/can-utils)
- [SocketCAN文档](https://www.kernel.org/doc/html/latest/networking/can.html)

## 🔧 管理命令

### 使用docker-compose
```bash
# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 重启服务
docker-compose restart

# 重新构建
docker-compose up -d --build
```

### 使用Docker
```bash
# 查看日志
docker logs -f udsctf-container

# 停止服务
docker stop udsctf-container

# 重启服务
docker restart udsctf-container

# 删除容器
docker rm -f udsctf-container
```

## 🧪 测试连接

运行测试脚本验证环境：
```bash
python3 test_ssh.py
```

## 📄 许可证

本项目仅供CTF比赛使用，请遵守相关法律法规。 