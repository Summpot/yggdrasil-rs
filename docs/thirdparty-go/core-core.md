# File: thirdparty/yggdrasil-go/src/core/core.go

Purpose: central node object; holds encryption, links, protocol handlers, nodeinfo, and lifecycle management for the Go daemon.

Key points
- `Core` embeds `phony.Inbox` actor; owns `iwe.PacketConn` (Ironwood encrypted transport), context/cancel, ed25519 keys, link manager (`links`), protocol handler (`proto`), logger, timers, and config (TLS, listeners, peerFilter, nodeinfo, allowed keys). Optional `pathNotify` callback.
- `New` validates TLS cert/key, sets logging, applies setup options in two phases (non-peer/listen first, then peers/listeners after links init). Builds TLS config, derives public key, constructs `PacketConn` with bloom transform and path notify, initializes protocol and links, sets nodeinfo, and starts listeners via `links.listen` for each configured address.
- IO: `ReadFrom`/`WriteTo` wrap PacketConn adding/removing leading session type byte; session proto packets are handed to `proto.handleProto`. `MTU` caps at 65535 minus overhead. `RetryPeersNow` kicks link actors; `Stop` cancels context, shuts links and PacketConn.

Rust parity
- Rust core is spread across crates (`yggdrasil-core` in `src/core.rs`, `yggdrasil-link`, `yggdrasil-routing`, `yggdrasil-session`). Uses tokio async instead of phony actor; encryption via Rust equivalents (ironwood? custom) and tracks links/sessions separately.
- Listener setup and peer retry mirror behavior conceptually; Rust lacks the phony actor model and uses async tasks/channels. Rust admin/routing integration recently added metrics and path/tree endpoints from link manager.
- MTU and path notify handling exist but with different abstractions; Rust uses typed packets over `WirePacketType` and session manager.
