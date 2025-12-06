# File: thirdparty/yggdrasil-go/src/config/config.go

Purpose: defines `NodeConfig` for yggdrasil-go, with key, peer, admin, multicast, TUN, and nodeinfo settings; provides default generation, parsing (HJSON/JSON), and PEM/TLS helpers.

Key points
- `NodeConfig` fields: `PrivateKey`/`PrivateKeyPath` plus `Certificate`, peer lists (`Peers`, `InterfacePeers`, `Listen`), admin listen address, multicast interface configs (regex, beacon/listen, port/priority/password), allowed public keys, TUN interface name/MTU, nodeinfo privacy and data, log lookups.
- `GenerateConfig` loads platform defaults (admin listen, multicast interfaces, ifname/MTU), creates new ed25519 key, empty peers/listeners, calls `postprocessConfig`.
- Parsing: `ReadFrom` loads bytes (handles UTF-16 BOM), seeds defaults via `GenerateConfig`, then `UnmarshalHJSON` and `postprocessConfig`. HJSON via `hjson-go`.
- `postprocessConfig` loads PEM private key if path set, ensures `Certificate` matches current key by generating self-signed cert when needed. Exposes PEM marshal/unmarshal helpers, self-signed cert generation (`notAfterNeverExpires` expiry), and key generation (`NewPrivateKey`).

Rust parity
- Rust config lives in `yggdrasil-config` crate and `NodeConfig` struct; supports HJSON parsing and default generation similar to Go. Rust splits defaults per platform files and derives TLS certs inside config too.
- Fields largely align (peers/interface peers, admin listen, multicast, nodeinfo, TUN). Rust uses strong typing (`PublicKey`, `Address`, `TunConfig`, `MulticastConfig`) and has serde-based parsing; no BOM handling logic noted. PEM export/import exposed via commands `export-key` etc.
