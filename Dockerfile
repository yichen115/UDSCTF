# 使用Ubuntu 20.04作为基础镜像
FROM ubuntu:20.04

# 设置时区和禁用交互式安装
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 切换到阿里云镜像源
RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

# 安装必要的软件包
RUN apt-get update && apt-get install -y \
    build-essential \
    can-utils \
    iproute2 \
    python3 \
    python3-pip \
    openssh-server \
    sudo \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

# 配置pip使用阿里云源
RUN mkdir -p ~/.pip && \
    echo "[global]" > ~/.pip/pip.conf && \
    echo "index-url = https://mirrors.aliyun.com/pypi/simple/" >> ~/.pip/pip.conf && \
    echo "trusted-host = mirrors.aliyun.com" >> ~/.pip/pip.conf

# 安装python-can库
RUN pip3 install python-can

# 创建CTF用户和工作目录
RUN useradd -m -s /bin/bash ctfuser && \
    echo "ctfuser:ctfpassword" | chpasswd && \
    mkdir -p /home/ctfuser/challenge

# 配置SSH服务
RUN mkdir -p /var/run/sshd && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "AllowUsers ctfuser" >> /etc/ssh/sshd_config

# 复制挑战文件到临时目录
COPY *.c *.h Makefile /tmp/build/
WORKDIR /tmp/build

# 编译UDS服务器
RUN make clean && make

# 将可执行文件放在系统目录中，选手无法访问
RUN mkdir -p /opt/udsctf && \
    cp uds_server /opt/udsctf/ && \
    chmod 700 /opt/udsctf/uds_server && \
    chown root:root /opt/udsctf/uds_server && \
    rm -rf /tmp/build

# 创建启动脚本
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# 创建清理脚本
COPY cleanup.sh /usr/local/bin/cleanup.sh
RUN chmod +x /usr/local/bin/cleanup.sh

# 创建权限设置脚本
COPY setup_permissions.sh /usr/local/bin/setup_permissions.sh
RUN chmod +x /usr/local/bin/setup_permissions.sh

# 设置用户权限限制
RUN chown ctfuser:ctfuser /home/ctfuser/challenge && \
    chmod 755 /home/ctfuser/challenge && \
    # 限制用户访问系统目录
    chmod 750 /home/ctfuser && \
    # 禁止访问源代码和可执行文件
    mkdir -p /home/ctfuser/.restricted && \
    echo "#!/bin/bash" > /home/ctfuser/.restricted/check_access.sh && \
    echo "if [[ \"\$1\" =~ \"/etc/|/proc/|/sys/|/dev/|/opt/|/usr/|/bin/|/sbin/|\.c$|\.h$|Makefile|uds_server\" ]]; then" >> /home/ctfuser/.restricted/check_access.sh && \
    echo "  echo \"错误: 不允许访问系统文件、可执行文件或源代码\"" >> /home/ctfuser/.restricted/check_access.sh && \
    echo "  exit 1" >> /home/ctfuser/.restricted/check_access.sh && \
    echo "fi" >> /home/ctfuser/.restricted/check_access.sh && \
    chmod +x /home/ctfuser/.restricted/check_access.sh && \
    chown root:root /home/ctfuser/.restricted/check_access.sh && \
    chmod 700 /home/ctfuser/.restricted

# 创建用户别名和限制 - 简化版本
RUN echo "alias find='echo \"错误: find命令被禁用\"'" >> /home/ctfuser/.bashrc && \
    echo "export PATH=/usr/local/bin:/usr/bin:/bin" >> /home/ctfuser/.bashrc && \
    echo "cd /home/ctfuser/challenge" >> /home/ctfuser/.bashrc && \
    echo "" >> /home/ctfuser/.bashrc && \
    echo "# 显示欢迎信息" >> /home/ctfuser/.bashrc && \
    echo "if [ -f /home/ctfuser/.welcome ]; then" >> /home/ctfuser/.bashrc && \
    echo "    cat /home/ctfuser/.welcome" >> /home/ctfuser/.bashrc && \
    echo "fi" >> /home/ctfuser/.bashrc && \
    echo "" >> /home/ctfuser/.bashrc && \
    echo "# 显示当前工作目录" >> /home/ctfuser/.bashrc && \
    echo "echo \"当前工作目录: \$(pwd)\"" >> /home/ctfuser/.bashrc && \
    echo "echo \"可用命令: python3, vim, cansend, candump, cangen, isotpdump, isotpsend\"" >> /home/ctfuser/.bashrc && \
    echo "echo \"\"" >> /home/ctfuser/.bashrc

# 删除编译工具（安全措施）
RUN apt-get remove -y build-essential gcc g++ make && \
    apt-get autoremove -y && \
    apt-get clean

# 暴露SSH端口
EXPOSE 22

# 启动脚本
ENTRYPOINT ["/usr/local/bin/start.sh"] 