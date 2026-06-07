FROM rust:1.78-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        clang \
        coreutils \
        curl \
        ethtool \
        findutils \
        git \
        grep \
        iproute2 \
        iptables \
        iputils-ping \
        libpcap-dev \
        libpcap0.8 \
        net-tools \
        openssh-server \
        pkg-config \
        procps \
        python3 \
        sed \
        tar \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN rustup default 1.78.0 \
    && mkdir -p /run/sshd /root/.ssh \
    && ln -sf "$(rustup which cargo)" /usr/local/bin/cargo \
    && ln -sf "$(rustup which rustc)" /usr/local/bin/rustc \
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
