# UDSCTF - UDS协议安全挑战

这是一个基于UDS（Unified Diagnostic Services）协议的CTF挑战环境，旨在测试对汽车诊断协议的理解和安全分析能力。挑战包含多个层次的flag获取，从基础的协议理解到高级的内存dump分析。

## 挑战概述

本挑战包含五个flag，难度递增：

1. **公开flag** - 可直接获取 (DID: `0xF190`)
2. **安全flag** - 需要级别1安全访问 (DID: `0xC1C2`)
3. **高级flag** - 需要级别3安全访问 (DID: `0xD1D2`)
4. **内存flag** - 需要级别5安全访问 + 内存dump分析 (0x23服务)
5. **启动flag** - 需要监听启动消息 (CAN ID: `0x7E8`)

## 环境配置

### 系统要求
- Docker
- Linux系统（支持CAN接口）
- Python 3.6+ (用于解题脚本)

### 快速启动
```bash
# 构建镜像
docker build -t udsctf .

# 运行容器
docker run -d --name udsctf --privileged -p 2222:22 udsctf

# SSH连接
ssh ctfuser@localhost -p 2222
# 密码: ctpassword
```

## 挑战内容详解

### 1. 公开flag获取
**难度**: ⭐  
**描述**: 基础的UDS协议理解，直接读取DID即可获得flag。

```bash
# CAN消息格式
7DF#0322F190
```

### 2. 安全flag获取 (级别1)
**难度**: ⭐⭐  
**描述**: 需要理解UDS安全访问机制，完成seed-key交换。

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

### 3. 高级flag获取 (级别3)
**难度**: ⭐⭐⭐  
**描述**: 需要切换到编程会话，并使用更复杂的密钥算法。

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

### 4. 内存flag获取 (级别5 + 内存dump)
**难度**: ⭐⭐⭐⭐  
**描述**: 最高难度的挑战，需要完成级别5安全访问，然后通过0x23服务dump内存分析ELF文件。

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

#### 4.3 ELF文件分析
- 程序基址: `0x40000000` (由Makefile中的`-Wl,-Ttext=0x40000000`设置)
- 服务端实现了ELF文件自映射，访问0x40000000时返回完整ELF文件内容
- 需要分析ELF头、程序头表、节头表等结构
- flag可能隐藏在ELF文件的各个段中

### 5. 启动flag获取
**难度**: ⭐  
**描述**: 监听服务器启动时发送的flag消息。

```bash
# 监听CAN总线消息
candump vcan0 | grep 7E8

# 或者重启ECU触发启动消息
7DF#021101
```

## 协议细节

### UDS服务详解
- **0x10**: DiagnosticSessionControl (会话控制)
  - 0x01: 默认会话
  - 0x02: 编程会话
- **0x11**: ECUReset (ECU复位)
  - 0x01: HardReset (硬复位)
- **0x22**: ReadDataByIdentifier (读取数据)
  - 0xF190: 公开flag
  - 0xC1C2: 安全flag (需要级别1)
  - 0xD1D2: 高级flag (需要级别3)
- **0x23**: ReadMemoryByAddress (读取内存)
  - 需要级别5安全访问
  - 支持ELF文件自映射到0x40000000
- **0x27**: SecurityAccess (安全访问)
  - 级别1: 0x01/0x02 (默认会话)
  - 级别3: 0x03/0x04 (编程会话)
  - 级别5: 0x05/0x06 (编程会话)
- **0x3E**: TesterPresent (维持会话)

### 安全访问级别
- **级别1**: 简单异或算法 `key = seed ^ 0xdeadbeef`
- **级别3**: 复杂位运算算法 (循环左移、异或、加法等)
- **级别5**: 最复杂算法 (多重异或、循环右移、位运算等)

### 会话管理
- 非默认会话需要每10秒发送0x3E维持
- 超时自动回退到默认会话
- 安全访问状态在会话切换时保持不变

### 内存访问特性
- 地址范围: `0x40000000 - 0x4FFFFFFF`
- 最大读取大小: 4KB (0x1000)
- ELF文件自映射: 访问0x40000000时返回完整ELF文件内容
- 支持多帧传输 (ISO-TP协议)

## 解题工具

### Python解题脚本
参考 `solve.py` 文件，包含完整的解题脚本：
- 自动化的安全访问流程
- 内存dump和分析功能
- ELF文件解析和flag查找
- 十六进制格式转换

### 关键函数
```python
def calc_key_level5(seed):  # 级别5密钥算法
def dump_memory(s, start_addr, size):  # 内存dump
def analyze_memory_dump(filename):  # 内存分析
def convert_dump_to_hex(input_file, output_file):  # 格式转换
```

## 技术要点

### ELF文件格式
- ELF头: 0x7F 0x45 0x4C 0x46
- 程序头表: 描述段信息
- 节头表: 描述节信息
- text段: 代码段
- data段: 数据段
- bss段: 未初始化数据段

### UDS协议栈
- ISO-TP (ISO 15765-2): 多帧传输协议
- CAN (ISO 11898): 底层通信协议
- UDS (ISO 14229): 诊断服务协议

### 安全机制
- 种子-密钥交换机制
- 会话级别控制
- 地址范围限制
- 大小限制保护

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
├── README.md            # 题目描述
└── 过程.md              # 开发过程记录
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