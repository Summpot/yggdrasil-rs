# thirdparty/yggdrasil-go/src/admin/getpeers.go, getpaths.go, gettree.go, addpeer.go, removepeer.go, options.go

## Overview
Admin socket handlers covering peer listing, tree/path inspection, peer add/remove, and optional lookup logging. These adapt Core APIs into JSON responses, including richer metrics (cost, latency, byte rates, error timestamps) and sorting.

## API surface & behaviour
- `getPeersHandler(req, res)`
  - Calls `core.GetPeers()` (Link actor + ironwood debug). Maps to `PeerEntry` with URI, inbound flag, priority, cost, latency, uptime seconds, rx/tx bytes and per-second rates, last error message & age, public key and IPv6 derived from key.
  - Sorting by `sort` param: default preferring outbound, then key/priority/cost/uptime; also `uptime` or `cost` modes via stable sort.
- `getPathsHandler`/`getTreeHandler`
  - Use `core.GetPaths()`/`core.GetTree()`; encode public/parent keys hex, derive IPv6, include path/sequence. Sort by public key.
- `addPeerHandler`/`removePeerHandler`
  - Parse URI, call `core.AddPeer` / `core.RemovePeer` with optional interface string. Errors on bad URI parsing.
- `options.go` lookup logger
  - Setup option types (`ListenAddress`, `LogLookups`). `LogLookups` installs ironwood debug lookup logger, keeps in-memory map of lookups for up to 24h, exposes admin handler `lookups` returning path and time per key.

## Comparison to yggdrasil-rs
- Rust admin server (`src/admin_server.rs`) exposes `getPeers/getTree/getPaths/addPeer/removePeer` but fields are slimmer:
  - No latency, cost, per-second rates, last_error_time, priority negotiation output. Tree/path data are synthesized from current links only (not full routing tree).
  - Sorting parameter absent; results unsorted beyond insertion order.
  - No `lookups` debug handler or lookup logging hook.
- Peer add/remove in Rust wrap `Links::connect_uri`/`disconnect` but only support `tls://` URIs; Go accepts multi-protocol URIs validated in core link layer.
- Go handlers rely on `core.Get*` that include ironwood debug info (root coords, costs) not present in Rust implementation, so parity would require extending link/routing/debug layers and admin payloads.
