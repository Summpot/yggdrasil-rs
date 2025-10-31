# Yggdrasil (Rust Implementation)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-LGPLv3-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-82%20passing-success.svg)]()

## Introduction

Yggdrasil is an experimental Rust implementation of a fully end-to-end encrypted IPv6 mesh network. This project aims to replicate the core functionality of the [original Go implementation](https://github.com/yggdrasil-network/yggdrasil-go) while leveraging Rust's memory safety and performance advantages.

Yggdrasil is lightweight, self-arranging, and allows pretty much any IPv6-capable application to communicate securely with other Yggdrasil nodes. It does not require IPv6 Internet connectivity - it also works over IPv4.

## ✨ New Features (2025-10-30)

### High Priority Features ✅
- **WebSocket Transport**: Full support for ws:// and wss:// for browser-based nodes
- **Enhanced Greedy Routing**: Tree-space coordinate-based routing with intelligent fallback
- **Admin API Enhancement**: Coords and Root information in getPeers and getSessions responses

### Medium Priority Features ✅
- **QUIC Connection Pool**: High-performance connection pooling with multiplexing support
- **Prometheus Metrics**: Comprehensive monitoring metrics for network traffic, peers, routes, and performance
- **Complete API Documentation**: Full Admin API and Rust library API reference

See [FEATURE_IMPLEMENTATION_SUMMARY.md](FEATURE_IMPLEMENTATION_SUMMARY.md) for detailed information.

## Supported Transport Protocols

- ✅ **TCP** - Traditional TCP connections
- ✅ **QUIC** - UDP-based secure transport with connection pooling
- ✅ **WebSocket (ws://)** - For browser nodes and HTTP-friendly environments
- ✅ **WebSocket Secure (wss://)** - TLS-encrypted WebSocket
- ⏳ **SOCKS5 Proxy** - Planned
- ⏳ **Unix Domain Sockets** - Planned

## Supported Platforms

This Rust implementation uses the `tun` crate which provides cross-platform TUN/TAP device support for:
- ✅ Linux (tested)
- ✅ macOS (via `tun` crate)
- ✅ Windows (via `tun` crate)
- ✅ FreeBSD (via `tun` crate)
- ✅ OpenBSD (via `tun` crate)

**Note**: TUN device operations require elevated privileges:
- **Linux**: Requires `CAP_NET_ADMIN` capability or root
- **macOS/Windows/BSD**: Typically requires administrator/root privileges

For production deployments, it's recommended to run Yggdrasil as a system service with appropriate capabilities.

## Quick Start

### Docker (Recommended)

The easiest way to run Yggdrasil:

```bash
# Using Docker Compose
docker-compose up -d

# Or build and run manually
./build-docker.sh
docker run -d --name yggdrasil --cap-add=NET_ADMIN --cap-add=NET_RAW --network host yggdrasil-rs
```

See [DOCKER_SERVICE_GUIDE.md](DOCKER_SERVICE_GUIDE.md) for detailed Docker instructions.

### System Service

Install Yggdrasil as a native system service (Linux/macOS/Windows):

```bash
# Generate configuration
yggdrasil gen-conf > /etc/yggdrasil/config.hjson

# Install and start service
sudo yggdrasil service install
sudo yggdrasil service start

# Check status
systemctl status yggdrasil  # Linux
```

Service commands: `install`, `start`, `stop`, `restart`, `uninstall`, `status`

See [DOCKER_SERVICE_GUIDE.md](DOCKER_SERVICE_GUIDE.md) for complete service management documentation.

## Building

If you want to build from source:

1. Install [Rust](https://www.rust-lang.org/) (requires Rust 1.70 or later)
2. Clone this repository
3. Run the build command:

```bash
cargo build --workspace --release
```

The compiled binaries will be available in `target/release/`:
- `yggdrasil` - Main node daemon
- `yggdrasilctl` - Control utility
- `genkeys` - Key generation tool
- `yggdrasil-bench` - Performance benchmark tool

## Running

### Generate configuration

To generate a configuration file in HJSON format (human-friendly, complete with comments):

```bash
./target/release/yggdrasil gen-conf > /path/to/yggdrasil.hjson
```

Or generate a plain JSON file (easy to manipulate programmatically):

```bash
./target/release/yggdrasil gen-conf --json > /path/to/yggdrasil.json
```

You will need to edit the configuration file to add or remove peers, modify listen addresses, enable/disable multicast, etc.

### Run Yggdrasil

To run with the generated configuration:

```bash
./target/release/yggdrasil run --config /path/to/yggdrasil.hjson
```

To run in auto-configuration mode (uses sane defaults and random keys at each startup):

```bash
./target/release/yggdrasil run --autoconf
```

You will likely need to run Yggdrasil as a privileged user or under `sudo`, unless you have permission to create TUN adapters. On Linux this can be done by giving the Yggdrasil binary the `CAP_NET_ADMIN` capability:

```bash
sudo setcap cap_net_admin=+ep ./target/release/yggdrasil
```

### Compatibility mode

For compatibility with the original Go implementation's command-line interface:

```bash
# Generate configuration
./target/release/yggdrasil compat --genconf --json

# Show IPv6 address
./target/release/yggdrasil compat --useconffile config.hjson --address

# Show subnet
./target/release/yggdrasil compat --useconffile config.hjson --subnet
```

## Project Structure

This is a Cargo workspace containing multiple crates:

```
yggdrasil/
├── crates/
│   ├── yggdrasil-core/    # Core library implementation
│   │   └── src/
│   │       ├── address.rs      # IPv6 address derivation
│   │       ├── config.rs       # Configuration management
│   │       ├── crypto.rs       # Cryptographic functions
│   │       ├── core.rs         # Core event loop
│   │       ├── link.rs         # Link management (TCP/QUIC)
│   │       ├── peer.rs         # Peer management
│   │       ├── router.rs       # Routing table
│   │       ├── tun_adapter.rs  # TUN device adapter
│   │       └── multicast.rs    # Multicast discovery
│   ├── yggdrasil/         # Main daemon executable
│   ├── yggdrasilctl/      # Control utility
│   └── genkeys/           # Key generator
├── thirdparty/
│   ├── yggdrasil-go/      # Reference Go implementation
│   └── ironwood/          # Ironwood routing library (reference)
└── Cargo.toml             # Workspace manifest
```

## Routing Architecture

This implementation uses a spanning tree-based routing approach inspired by [Ironwood](https://github.com/Arceliar/ironwood):

### Spanning Tree Protocol
- Each node maintains its position in a network-wide spanning tree
- Root selection is deterministic (smallest public key)
- Parent selection based on distance to root
- Automatic failover and self-healing on link failures
- CRDT-Set semantics for eventual consistency

### Coordinate-Based Routing
- Each node's position is represented as coordinates in tree-space
- Packets are routed greedily toward the destination in the metric space
- Efficient with O(1) state per peer
- Converges as fast as the spanning tree itself

### Key Features
- No DHT required (simplified architecture)
- Soft-state protocol with timeout-based cleanup
- Resilient to network partitions and topology changes
- Compatible with Ironwood's design principles

See [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) for detailed implementation notes.

## Documentation

Development documentation is available in [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

Key topics:
- [Workspace Structure](.github/copilot-instructions.md#workspace-structure)
- [Configuration System](.github/copilot-instructions.md#configuration-system-configrs)
- [Address Derivation](.github/copilot-instructions.md#address-system-addressrs)
- [Cryptography](.github/copilot-instructions.md#cryptography-cryptors)
- [Building and Testing](.github/copilot-instructions.md#building-and-testing)

## Development Status

### Completed ✅

- Configuration system (HJSON/JSON/TOML)
- Ed25519 key generation and management
- IPv6 address derivation from public keys (Go-compatible)
- Cryptographic stack (signing, key exchange, encryption)
- **Spanning tree protocol** (CRDT-Set style, Ironwood-based)
- **Coordinate-based routing** (tree-space greedy routing)
- Routing table with automatic cleanup
- Peer management with connection lifecycle
- Core event loop integration
- TCP link management
- QUIC transport support
- WebSocket support (ws:// and wss://)
- Handshake protocol (v0.5 compatible)
- TUN device adapter (cross-platform via `tun` crate)
- Admin API (Unix socket)
- CLI commands and compatibility layer

### In Progress 🚧

- Spanning tree integration into Core event loop
- Tree announcement gossip protocol
- Coordinate updates on topology changes
- Multicast discovery refinement

### Planned 📋

- Bloom filter-based node lookup (Ironwood-style)
- Pathfinding for backup routes
- Performance optimization
- Enhanced metrics and monitoring

## Testing

Run the test suite:

```bash
# Test all crates
cargo test --workspace

# Test specific crate
cargo test -p yggdrasil-core

# Test with logging enabled
RUST_LOG=debug cargo test
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

Before submitting, please ensure:
- Code builds without warnings: `cargo build --workspace`
- Tests pass: `cargo test --workspace`
- Code is formatted: `cargo fmt --all`
- Clippy is happy: `cargo clippy --workspace -- -D warnings`

## License

This code is released under the terms of the LGPLv3. For more details, see [LICENSE](LICENSE).

## Acknowledgments

Based on the original [Yggdrasil Network](https://github.com/yggdrasil-network/yggdrasil-go) implementation in Go.

## Community

For questions or discussion about Yggdrasil (both Go and Rust implementations):
- Matrix: [#yggdrasil:matrix.org](https://matrix.to/#/#yggdrasil:matrix.org)
- IRC: `#yggdrasil` on [libera.chat](https://libera.chat)
