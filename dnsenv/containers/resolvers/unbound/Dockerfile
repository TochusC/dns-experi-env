# Debian镜像
FROM debian:latest

ENV UNBOUND_VERSION 1.22.0

# 设置维护者信息
LABEL maintainer="tochusc"


# 更新包列表并安装构建Unbound所需的依赖
RUN apt-get -y update \
    && apt-get -y upgrade \
    && apt-get install -y build-essential libexpat1-dev libssl-dev wget dnsutils

# 下载Unbound源代码
RUN wget https://nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION}.tar.gz \
    && tar xvf unbound-${UNBOUND_VERSION}.tar.gz \
    && rm unbound-${UNBOUND_VERSION}.tar.gz

# 编译并安装Unbound
RUN cd unbound-${UNBOUND_VERSION} \
    && ./configure \
    && make \
    && make install

RUN groupadd -r unbound && useradd -r -g unbound unbound

# 开放DNS服务器默认端口
EXPOSE 53/udp
EXPOSE 53/tcp

# 启动Unbound
CMD ["unbound", "-d"]
