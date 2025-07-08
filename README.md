# UDSCTF - UDS协议安全挑战

这是一个基于UDS（Unified Diagnostic Services）协议的CTF挑战环境，旨在测试对汽车诊断协议的理解和安全分析能力。挑战包含多个层次的flag获取，从基础的协议理解到高级的内存dump分析。

所有代码由 AI 编写，可能存在错误（iso14229.c / .h 来源于：https://github.com/driftregion/iso14229）

## 挑战概述

本挑战包含五个flag，难度递增：

1. **读取VIN码获取flag** - 可直接获取 (DID: `0xF190`)
2. **通过安全访问级别1读取DID：0xC1C2获取flag** - 需要级别1安全访问 (DID: `0xC1C2`)
3. **通过安全访问级别3读取DID：0xD1D2获取flag** - 需要级别3安全访问 (DID: `0xD1D2`)
4. **通过安全访问级别5读取内存获取flag** - 需要级别5安全访问 + 内存dump分析 (0x23服务)
5. **系统启动时会往外发送flag，复位即可获取flag** - 需要监听启动消息 (CAN ID: `0x7E8`)

## 快速开始

```bash
# 构建&运行镜像
./deploy.sh

# SSH连接即可解题
ssh ctfuser@localhost -p 2222     # 密码: ctpassword
```

## 挑战内容详解

### 1. VIN flag获取
**难度**: ⭐  
**描述**: 基础的UDS协议理解，直接读取DID F190即可获得flag。

```bash
# CAN消息格式
7DF#0322F190
```

### 2. 27 Level1 flag获取 (安全级别1)
**难度**: ⭐⭐  
**描述**: 需要理解UDS安全访问机制，完成seed-key交换，通过安全访问Level1后读取DID：C1C2。

```bash
# 步骤1: 请求seed
7DF#022701

# 步骤2: 计算key (key = seed ^ 0xdeadbeef)
# 假设收到seed: 0x12345678
# 则key = 0x12345678 ^ 0xdeadbeef = 0xccd9f897

# 步骤3: 发送key
7DF#062702CCD9F897

# 步骤4: 读取flag
7DF#0322C1C2
```

### 3. 27 Level3 flag获取 (安全级别3)
**难度**: ⭐⭐⭐  
**描述**: 需要切换到编程会话，并使用更复杂的密钥算法，通过安全访问Level3后读取DID：C1C2。

```bash
# 步骤1: 切换到编程会话
7DF#021002

# 步骤2: 请求级别3 seed
7DF#022703

# 步骤3: 计算级别3 key (复杂算法)
# key = ((seed << 7) | (seed >> 25)) ^ 0xCAFEBABE + 0x12345678
# key = (key & 0xFFFF0000) | ((key & 0x0000FFFF) ^ 0xABCD) ^ 0xDEADBEEF

# 步骤4: 发送级别3 key
7DF#062704 + calculated_key

# 步骤5: 读取flag
7DF#0322D1D2
```

### 4. dump内存获取flag (安全级别5 + 内存dump)
**难度**: ⭐⭐⭐⭐  
**描述**: 最高难度的挑战，需要完成级别5安全访问，然后通过0x23服务dump内存寻找flag。

#### 4.1 级别5安全访问
```bash
# 步骤1: 请求级别5 seed
7DF#022705

# 步骤2: 计算级别5 key (最复杂算法)
# key = seed ^ 0x12345678 ^ 0x87654321
# key = (key >> 13) | (key << 19)
# key = (key & 0xFF00FF00) | ((key & 0x00FF00FF) ^ 0x55555555)
# key = key + 0xDEADBEEF ^ 0xCAFEBABE

# 步骤3: 发送级别5 key
7DF#062706 + calculated_key
```

#### 4.2 内存dump分析
```bash
# 使用0x23 ReadMemoryByAddress服务
# 格式: 0x23 + 格式标识符 + 地址 + 大小
# 格式标识符0x14表示: 1字节大小 + 4字节地址

# 示例: 读取0x40000000开始的80字节
7DF#0723144000000050
```

#### 4.3 UDS Server 内存分析
- 程序基址: `0x40000000`
- 服务端实现了ELF文件自映射，访问0x40000000时返回完整ELF文件内容，在其中可获得flag

### 5. 复位启动flag获取
**难度**: ⭐  
**描述**: 监听CAN总线，复位重启服务获取flag消息。

```bash
# 监听CAN总线消息
candump vcan0 | grep 7E8

# 或者重启ECU触发启动消息
7DF#021101
```

## 快速部署

```bash
# 构建并运行
docker build -t udsctf:latest .
docker run -d --name udsctf-container --privileged -p 2222:22 udsctf:latest

# SSH连接
ssh ctfuser@localhost -p 2222
# 密码: ctfpassword

# 启动CAN接口
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 运行解题脚本
python3 solve.py
```

## 文件结构
```
UDSCTF/
├── uds_server.c          # UDS服务器实现
├── iso14229.c           # ISO14229协议栈
├── iso14229.h           # 协议头文件
├── solve.py             # 解题脚本
├── Makefile             # 编译配置
├── Dockerfile           # Docker配置
├── docker-compose.yml   # Docker编排
└── README.md            # 题目描述
```

## 评分标准
- 公开flag: 10分
- 安全flag: 20分  
- 高级flag: 30分
- 内存flag: 35分
- 启动flag: 5分
- **总分: 100分**

## 提示
1. 仔细分析UDS协议格式和ISO-TP多帧传输
2. 理解ELF文件格式有助于内存分析
3. 使用十六进制编辑器查看dump文件
4. 注意安全访问的会话要求
5. 多帧传输需要正确处理流控帧

祝你好运！🚗🔧 
