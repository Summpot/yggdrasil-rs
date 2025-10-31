# syntax=docker/dockerfile:1.4
# Yggdrasil Rust Implementation - Multi-stage Docker Build
# Simplified build process using Docker Buildx cache

# ===== Build Stage =====
FROM rust:alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    openssl-dev \
    openssl \
    cmake \
    musl-dev \
    curl \
    bash \
    clang \
    pkgconfig

# Install cargo-binstall for faster tool installation
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

# Install sccache and wild-linker
RUN cargo binstall -y sccache wild-linker

# Configure wild linker for x86_64-unknown-linux-musl
RUN printf '[target.x86_64-unknown-linux-musl]\nlinker = "clang"\nrustflags = ["-Clink-arg=--ld-path=wild"]\n' > /usr/local/cargo/config.toml

# Configure sccache
ENV RUSTC_WRAPPER="/usr/local/cargo/bin/sccache" \
    SCCACHE_DIR="/sccache" \
    SCCACHE_CACHE_SIZE="10G" \
    CARGO_INCREMENTAL="0"

# Copy all source code
COPY Cargo.toml Cargo.lock benchmarks.toml ./
COPY crates/ ./crates/

# Build the binaries with sccache and cache mounts
RUN --mount=type=cache,id=yggdrasil-sccache,target=/sccache,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --workspace --release --target x86_64-unknown-linux-musl && \
    sccache --show-stats && \
    # Copy binaries out of cache directory
    mkdir -p /binout && \
    cp /build/target/x86_64-unknown-linux-musl/release/yggdrasil /binout/ && \
    cp /build/target/x86_64-unknown-linux-musl/release/yggdrasilctl /binout/ && \
    cp /build/target/x86_64-unknown-linux-musl/release/genkeys /binout/ && \
    cp /build/target/x86_64-unknown-linux-musl/release/yggdrasil-bench /binout/

# ===== Runtime Stage =====
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    iproute2 \
    iptables

# Copy binaries from builder
COPY --from=builder /binout/yggdrasil /usr/local/bin/yggdrasil
COPY --from=builder /binout/yggdrasilctl /usr/local/bin/yggdrasilctl
COPY --from=builder /binout/genkeys /usr/local/bin/genkeys
COPY --from=builder /binout/yggdrasil-bench /usr/local/bin/yggdrasil-bench

# Create configuration directory
RUN mkdir -p /etc/yggdrasil

# Generate default configuration
RUN yggdrasil gen-conf > /etc/yggdrasil/config.hjson

# Expose default ports
# 9001: Main peer port (TCP/QUIC/WebSocket)
# 9002: Multicast discovery port
# 9003: Admin socket (typically Unix socket)
EXPOSE 9001 9002

# Set working directory
WORKDIR /etc/yggdrasil

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD yggdrasilctl get-self || exit 1

# Run Yggdrasil
ENTRYPOINT ["yggdrasil"]
CMD ["run", "--config", "/etc/yggdrasil/config.hjson"]
