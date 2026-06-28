# syntax=docker/dockerfile:1
FROM rust:1.78-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=always

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        clang \
        curl \
        file \
        git \
        iproute2 \
        iputils-ping \
        iw \
        libpcap-dev \
        libpcap0.8 \
        libudev-dev \
        pkg-config \
        procps \
        protobuf-compiler \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-venv \
        python3-wheel \
        tcpdump \
        wireless-regdb \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /work

COPY image/entrypoint.sh /usr/local/bin/libcrafter-appliance-entrypoint

RUN chmod 0755 /usr/local/bin/libcrafter-appliance-entrypoint

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/libcrafter-appliance-entrypoint"]
CMD ["/bin/bash"]
