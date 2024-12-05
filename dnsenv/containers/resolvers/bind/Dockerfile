# Debian镜像
FROM debian:latest

# 设置维护者信息
LABEL maintainer="tochusc"

# 设置BIND版本
ENV BIND_VERSION 9.21.2

# 避免在安装软件包时出现交互提示
ENV DEBIAN_FRONTEND noninteractive

# 更新包列表并安装依赖
RUN apt-get -y update \
    && apt-get -y upgrade \
    && apt-get -y install build-essential libssl-dev libperl-dev \
    libcap-dev wget tar libuv1 pkg-config \
    libuv1-dev bind9utils liburcu-dev dnsutils


# 限于网络环境，使用本地文件代替远程下载
# RUN wget https://downloads.isc.org/isc/bind9/${BIND_VERSION}/bind-${BIND_VERSION}.tar.xz
COPY ./bind/bind-${BIND_VERSION}.tar.xz /usr/local/src/bind-${BIND_VERSION}.tar.xz

# 安装BIND，--enalbe-syscalls参数用于支持系统调用,
# --with-openssl启用OpenSSL支持，用于DNSSEC和其他加密功能，
# --enable-openssl-BIND_VERSION-check启用OpenSSL版本检查，
# --enable-ipv6启用IPv6支持，--disable-linux-caps禁用Linux特权分离
# --prefix=/var/named/chroot指定安装目录
# --enable-threads启用线程支持
# --disable-doh禁用DNS over HTTPS
RUN cd /usr/local/src && \
    tar xvf bind-${BIND_VERSION}.tar.xz && \
    mv bind-${BIND_VERSION} bind && \
    rm bind-${BIND_VERSION}.tar.xz
RUN cd /usr/local/src/bind && \
    ./configure --enable-syscalls --prefix=/var/named/chroot --disable-doh --enable-threads --with-openssl --enable-openssl-BIND_VERSION-check --enable-ipv6 --disable-linux-caps && \
    chown -R root:root /usr/local/src/bind && \
    make && \
    make install

# 创建设备文件
RUN mkdir -p /var/named/chroot/dev && \
    mknod -m 666 /var/named/chroot/dev/null c 1 3 && \
    mknod -m 666 /var/named/chroot/dev/random c 1 8

# 创建必要目录
RUN mkdir -p /var/named/chroot/data && \
    mkdir -p /var/named/chroot/var/log && \
    mkdir -p /var/named/chroot/var/named

# 创建符号链接
RUN  ln -s /var/named/chroot/etc/named.conf /etc/named.conf

# 开放DNS服务器默认端口
EXPOSE 53/udp
EXPOSE 53/tcp

# 启动BIND
# -t: 指定chroot环境根目录
# -c: 指定配置文件
# -g: 在前台运行，并将日志输出到标准输出
# -d: 指定日志级别为debug 99
CMD [ "/var/named/chroot/sbin/named", \
    "-t", "/var/named/chroot", \
    "-c", "/etc/named.conf",    \
    "-g", "-d", "99", "-4" ]

