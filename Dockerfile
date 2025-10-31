# syntax=docker/dockerfile:1.4
# Yggdrasil Rust Implementation - Runtime Docker Image
# This Dockerfile uses pre-built musl binaries from the CI/CD pipeline.
# Binaries should be placed in the binaries/ directory before building.

FROM alpine:latest

ARG TARGETARCH

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    iproute2 \
    iptables

# Copy pre-built binaries from binaries directory
COPY binaries/yggdrasil /usr/local/bin/yggdrasil
COPY binaries/yggdrasilctl /usr/local/bin/yggdrasilctl
COPY binaries/genkeys /usr/local/bin/genkeys
COPY binaries/yggdrasil-bench /usr/local/bin/yggdrasil-bench

# Set permissions
RUN chmod +x /usr/local/bin/yggdrasil \
    /usr/local/bin/yggdrasilctl \
    /usr/local/bin/genkeys \
    /usr/local/bin/yggdrasil-bench

# Create configuration directory
RUN mkdir -p /etc/yggdrasil

# Generate default configuration
RUN yggdrasil gen-conf > /etc/yggdrasil/config.hjson

# Expose default ports
# 9001: Main peer port (TCP/QUIC/WebSocket)
# 9002: Multicast discovery port
EXPOSE 9001 9002

# Set working directory
WORKDIR /etc/yggdrasil

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD yggdrasilctl get-self || exit 1

# Run Yggdrasil
ENTRYPOINT ["yggdrasil"]
CMD ["run", "--config", "/etc/yggdrasil/config.hjson"]


