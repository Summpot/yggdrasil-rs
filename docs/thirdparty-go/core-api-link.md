# thirdparty/yggdrasil-go/src/core/api.go & link.go

## Overview
Exposes public Core APIs for admin RPC (self/peers/tree/paths/sessions, peer management, listeners) and implements the link manager responsible for dialing/listening over multiple transports (TCP/TLS/UNIX/SOCKS/QUIC/WS/WSS), handshakes, backoff, metrics, and allowed-key enforcement.

## api.go – API surface & behaviour
- Data structs: `SelfInfo`, `PeerInfo`, `TreeEntryInfo`, `PathEntryInfo`, `SessionInfo` with routing, latency, bytes, error timestamps, priority, and root/coord fields.
- `GetSelf()`: returns public key and routing entry count via ironwood debug state.
- `GetPeers()`: merges link actor state (URI, errors, byte/bitrate counters, uptime, inbound/outbound) with ironwood debug info (keys, root, port, priority, latency, cost).
- `GetTree()/GetPaths()`: expose spanning tree/path info from ironwood debug.
- `GetSessions()`: exposes session counters and uptime from ironwood.
- Listener/peer control: `Listen` and `ListenLocal` (with optional AllowedPublicKeys bypass), `Address()/Subnet()` key-derived IPv6 info, `SetLogger`, `AddPeer`, `RemovePeer`, `CallPeer`, `PublicKey` getter.
- Admin wiring: `SetAdmin` registers handlers (`getNodeInfo`, `debug_remote*`) via provided AddHandler.

## link.go – Link manager highlights
- Supports schemas: tcp, tls, unix, socks/sockstls, quic, ws, wss. Each has a protocol module implementing `dial`/`listen`.
- Link types: persistent, ephemeral, incoming; exponential backoff with configurable `maxbackoff` (min 5s, default ~68m) and immediate `kick` channel.
- Options parsed from URI query: pinned ed25519 keys (`key=`), `priority`, `password` (<= blake2b length), `maxbackoff`, TLS SNI override (`sni=`). Also filters invalid priority/backoff/password/SNI.
- Connection lifecycle:
  - `add`: canonicalises URI (strips query for map key), stores link state, spawns goroutine to repeatedly dial, track errors, and run `handler`.
  - `handler`: performs version handshake (`version_metadata`), enforces not connecting to self, optional pinned-key check, AllowedPublicKeys check for inbound unless `local` flag, computes remote IPv6, calls `Core.HandleConn`, logs connect/disconnect with direction and priority negotiation.
  - Incoming `listen`: starts protocol listener, wraps accepted conn in `linkConn` with byte counters, manages state map per-connection, and invokes `handler` with `local` flag for multicast cases.
  - Backoff/reset logic around handshake success/failure; persistent peers retain state and errors for admin visibility.
- Metrics: per-connection atomic rx/tx and per-second `rxrate/txrate` computed by `_updateAverages` timer; uptime stored per connection.
- Safety: rejects duplicate live links; enforces AllowedPublicKeys for inbound; errors surfaced per link state for admin.

## Comparison to yggdrasil-rs
- Admin API parity: Rust `src/admin_server.rs` exposes `getSelf/getPeers/getTree/getPaths/getSessions`, but data is far thinner—no latency/rate/error timestamps/root/coords, and routing/tree/path data are placeholders derived only from live links. No remote debug queries (`debug_remote*`) hooks like `SetAdmin`.
- Peer control: Rust `AdminServer` supports `addPeer/removePeer`, mapping to `Links::connect_uri`/`disconnect`, but lacks `CallPeer` one-shot behavior and `ListenLocal` equivalent.
- Transport support: Rust `yggdrasil-link` currently restricts URIs to TLS (`tls://`) over TCP with self-signed certs. Go supports TCP/TLS/UNIX/SOCKS/QUIC/WS/WSS plus SNI/pinned-key/password/max-backoff knobs and peer filtering (`peerFilter`).
- Handshake/options: Rust handshake uses `perform_handshake` with password and priority, but lacks pinned-key enforcement, SNI handling, per-link backoff tuning, and per-link `maxbackoff`/priority parsing from URI query.
- Metrics: Rust `Links` tracks rx/tx bytes and uptime flags but no per-second rates or last error timestamps; admin output omits latency/cost/root data.
- IPv6/subnet helpers: Rust `Core` exposes `address()`/`subnet()`; parity exists but not wired into admin peer listings (currently derives ipAddress separately for sessions/peers).
