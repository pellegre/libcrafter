FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        ethtool \
        findutils \
        grep \
        iproute2 \
        iputils-ping \
        libpcap0.8 \
        net-tools \
        openssh-server \
        procps \
        sed \
        tar \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh \
    && sed -i \
        -e 's/^#\?PermitRootLogin .*/PermitRootLogin prohibit-password/' \
        -e 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' \
        -e 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' \
        -e 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
        /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/libcrafter-wire-entrypoint

RUN chmod 0755 /usr/local/bin/libcrafter-wire-entrypoint

EXPOSE 22

ENTRYPOINT ["/usr/bin/bash", "/usr/local/bin/libcrafter-wire-entrypoint"]
