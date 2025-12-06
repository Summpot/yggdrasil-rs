FROM alpine:latest

ARG TARGETARCH

RUN apk add --no-cache \
    ca-certificates \
    iproute2 \
    iptables

COPY binaries/yggdrasil /usr/local/bin/yggdrasil

RUN chmod +x /usr/local/bin/yggdrasil

RUN mkdir -p /etc/yggdrasil

RUN yggdrasil gen-conf > /etc/yggdrasil/yggdrasil.conf

WORKDIR /etc/yggdrasil

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD yggdrasil get-self || exit 1

ENTRYPOINT ["yggdrasil"]
CMD ["run", "--config", "/etc/yggdrasil/yggdrasil.conf"]


