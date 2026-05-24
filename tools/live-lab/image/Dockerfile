FROM rust:1-bookworm

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        file \
        g++ \
        gcc \
        git \
        iproute2 \
        iputils-ping \
        jq \
        libpcap-dev \
        make \
        net-tools \
        pkg-config \
        python3 \
        xxd \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -sf /root/.local/bin/uv /usr/local/bin/uv

RUN rustup component add clippy rustfmt

ENV PATH="/root/.local/bin:${PATH}"
ENV LIBCRAFTER_PROJECT_ROOT="/workspace/libcrafter"

COPY entrypoint.sh /usr/local/bin/libcrafter-live-entrypoint
RUN chmod +x /usr/local/bin/libcrafter-live-entrypoint

WORKDIR /workspace/libcrafter
ENTRYPOINT ["/usr/local/bin/libcrafter-live-entrypoint"]
CMD ["check"]
