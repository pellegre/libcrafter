FROM rust:1-bookworm

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        bison \
        build-essential \
        ca-certificates \
        clang \
        curl \
        file \
        flex \
        g++ \
        gcc \
        git \
        iproute2 \
        iputils-ping \
        jq \
        libpcap-dev \
        libtool \
        m4 \
        make \
        net-tools \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        xxd \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/scapy-venv \
    && /opt/scapy-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/scapy-venv/bin/pip install --no-cache-dir scapy

RUN rustup component add clippy rustfmt

ENV PATH="/opt/scapy-venv/bin:${PATH}"
ENV LIBCRAFTER_PROJECT_ROOT="/workspace/libcrafter"

COPY entrypoint.sh /usr/local/bin/libcrafter-live-entrypoint
RUN chmod +x /usr/local/bin/libcrafter-live-entrypoint

WORKDIR /workspace/libcrafter
ENTRYPOINT ["/usr/local/bin/libcrafter-live-entrypoint"]
CMD ["check"]
