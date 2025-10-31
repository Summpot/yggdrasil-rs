# Yggdrasil Rust Implementation - Multi-stage Docker Build
# Supports Docker Buildx cache mounts for faster builds

# ===== Build Stage =====
FROM rust:1.82-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy workspace manifest first for better caching
COPY Cargo.toml Cargo.lock ./
COPY benchmarks.toml ./

# Copy all crate manifests to establish dependencies
COPY crates/yggdrasil-core/Cargo.toml ./crates/yggdrasil-core/
COPY crates/yggdrasil/Cargo.toml ./crates/yggdrasil/
COPY crates/yggdrasilctl/Cargo.toml ./crates/yggdrasilctl/
COPY crates/genkeys/Cargo.toml ./crates/genkeys/
COPY crates/yggdrasil-bench/Cargo.toml ./crates/yggdrasil-bench/

# Create dummy source files to cache dependencies
RUN mkdir -p crates/yggdrasil-core/src && \
    echo "pub const VERSION: &str = \"0.1.0\";" > crates/yggdrasil-core/src/lib.rs && \
    mkdir -p crates/yggdrasil/src && \
    echo "fn main() {}" > crates/yggdrasil/src/main.rs && \
    mkdir -p crates/yggdrasilctl/src && \
    echo "fn main() {}" > crates/yggdrasilctl/src/main.rs && \
    mkdir -p crates/genkeys/src && \
    echo "fn main() {}" > crates/genkeys/src/main.rs && \
    mkdir -p crates/yggdrasil-bench/src && \
    echo "fn main() {}" > crates/yggdrasil-bench/src/main.rs

# Build dependencies with Buildx cache mount
# This layer will be cached and reused unless Cargo.toml changes
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --workspace --release && \
    rm -rf crates/*/src

# Copy actual source code
COPY crates/ ./crates/

# Build the actual binaries with cache mounts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --workspace --release && \
    # Copy binaries out of cache directory
    cp /build/target/release/yggdrasil /yggdrasil && \
    cp /build/target/release/yggdrasilctl /yggdrasilctl && \
    cp /build/target/release/genkeys /genkeys

# ===== Runtime Stage =====
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /yggdrasil /usr/local/bin/yggdrasil
COPY --from=builder /yggdrasilctl /usr/local/bin/yggdrasilctl
COPY --from=builder /genkeys /usr/local/bin/genkeys

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
