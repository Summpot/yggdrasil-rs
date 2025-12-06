# thirdparty/yggdrasil-go/src/core/link_tls.go, link_tcp*.go, options.go

## Overview
Transport helpers for the Core link manager: raw TCP dial/listen with interface binding and platform socket tweaks, TLS wrapper with SNI/config cloning, plus startup setup options (peers, listeners, peer filters, node info, allowed keys).

## API surface & behaviour
- `linkTCP`
  - `dial`: uses `findSuitableIP` + `dialerFor`, 5s timeout, keepalive disabled. Supports link-local with zone, optional source interface selection.
  - `listen`: binds with optional source interface zone suffix.
  - `dialerFor`: when `sintf` provided, validates interface up, picks a source addr matching dst family/scope, sets `LocalAddr`, and chooses control fn:
    - Linux: `getControl` wraps `BindToDevice` (SO_BINDTODEVICE).
    - Darwin: `tcpContext` enables `SO_RECV_ANYIF` for listening.
    - Others: no-op control.
- `linkTLS`
  - Wraps TCP dial/listen; clones core TLS config per dial; enforces TLS1.2–1.3, sets SNI from hostname or `options.tlsSNI`; listener is `tls.NewListener` over TCP listener with keepalive disabled.
- `options.go` (Core `_applyOption` and SetupOption types)
  - Handles config-time options: `Peer` (URI + source iface) added as persistent link (ignores duplicate); `ListenAddress` appended to listener set; `PeerFilter` closure stored; `NodeInfo` map and `NodeInfoPrivacy`; `AllowedPublicKey` added to allowlist map.

## Comparison to yggdrasil-rs
- Rust `yggdrasil-link` only supports TLS over TCP with self-signed certs and does not expose per-dial interface binding or SO_BINDTODEVICE; source interface selection is absent.
- Rust handshake client ignores SNI entirely; Go sets SNI from hostname or explicit `sni` query.
- Rust listeners don’t adjust socket options (no RECV_ANYIF/BindToDevice analogs) and keepalive config differs.
- Setup options: Rust config path lacks direct equivalents for `PeerFilter`, `NodeInfo` injection, or per-peer source interface binding; allowed keys exist but are enforced in admin server differently.
- Protocol coverage: Go has multiple link schemes (tcp/tls/etc.) while Rust is restricted to tls:// URIs; peer addition in Rust validates only TLS.
