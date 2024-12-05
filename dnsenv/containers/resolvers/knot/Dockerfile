# Debian镜像
FROM debian:latest

# 设置维护者信息
LABEL maintainer="tochusc"

# 安装Knot Resolver
RUN apt-get -y update \
    && apt-get -y upgrade \
    && apt-get -y install apt-transport-https ca-certificates wget dnsutils \
    && wget -O /usr/share/keyrings/cznic-labs-pkg.gpg https://pkg.labs.nic.cz/gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-resolver bookworm main" | tee /etc/apt/sources.list.d/cznic-labs-knot-resolver.list \
    && apt-get -y update \
    && apt-get -y install knot-resolver

# 创建Knot DNS配置目录
RUN mkdir -p /etc/knot

# 开放DNS服务器默认端口
EXPOSE 53/udp
EXPOSE 53/tcp

# 设置容器启动时运行的命令

CMD ["kresd", "-n", "-c", "/etc/knot/kresd.conf"]