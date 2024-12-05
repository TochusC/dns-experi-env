FROM debian:latest

ENV GO_VERSION 1.23.2

LABEL maintainer=t0chus

# 安装依赖
RUN apt-get -y update \
    && apt-get -y upgrade \
    && apt-get -y install iptables wget dnsutils

# 安装GO语言
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH="/usr/local/go_workspace"

# 开放DNS服务器默认端口
EXPOSE 53/udp
EXPOSE 53/tcp

# 设置工作目录
WORKDIR /usr/local

# 启动脚本
# CMD iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP && go run dns_auth.go
CMD iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP && tail -f /dev/null