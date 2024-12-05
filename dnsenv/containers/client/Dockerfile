FROM python:3.9-alpine

RUN apk add bind-tools

# 切换至虚拟环境
ENV PATH="/opt/venv/bin:$PATH"

# 安装Scapy和pcapy
RUN pip install scapy

# 设置工作目录
WORKDIR /usr/local
