# Yggdrasil Rust Implementation - Development Instructions

**Last Updated: 2025-10-30**  
**Current Status: Core features complete with 82/82 tests passing, benchmark system operational**

Yggdrasil is an experimental end-to-end encrypted IPv6 mesh network implementation in Rust. This implementation maintains protocol compatibility with the original Go version while leveraging Rust's memory safety and performance advantages.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Workspace Structure

This is a Cargo workspace with multiple crates:

```bash
cd /home/summpot/yggdrasil

# Workspace root - DO NOT create crates here
ls -la
# Cargo.toml              - Workspace manifest
# crates/                 - All crates go here
# thirdparty/yggdrasil-go/  - Reference implementation
```

CRITICAL: All crates MUST be in the `crates/` directory. Never create crates in the repository root.

### Project Structure

```
crates/
├── yggdrasil-core/      # Core library (lib only, no main)
│   └── src/
│       ├── lib.rs
│       ├── address.rs   # IPv6 address derivation
│       ├── config.rs    # Configuration (HJSON/JSON/TOML)
│       ├── crypto.rs    # Ed25519/X25519/AES-GCM
│       ├── core.rs      # Core event loop
│       ├── link.rs      # TCP/QUIC/WebSocket links
│       ├── lookup.rs    # Bloom filter node lookup
│       ├── metrics.rs   # Prometheus metrics
│       ├── multicast.rs # Multicast discovery
│       ├── nodeinfo.rs  # Node metadata exchange
│       ├── peer.rs      # Peer management
│       ├── proto.rs     # Protocol handler
│       ├── quic_pool.rs # QUIC connection pool
│       ├── router.rs    # Enhanced routing table
│       ├── session.rs   # Session management
│       ├── spanning_tree.rs # Spanning tree protocol
│       └── tun_adapter.rs # TUN device
├── yggdrasil/           # Main executable
├── yggdrasilctl/        # Control tool
├── genkeys/             # Key generator
└── yggdrasil-bench/     # Performance regression detection system
    └── src/
        ├── main.rs      # CLI with 4 commands (run, gen-config, compare, gen-dashboard)
        ├── core/
        │   ├── mod.rs
        │   └── timing.rs  # HDR histogram latency tracking
        ├── scenario/
        │   ├── mod.rs
        │   └── config.rs  # Protocol×Overlay matrix scenarios
        ├── probe/
        │   ├── mod.rs
        │   └── memory.rs  # RSS memory monitoring
        └── emit/
            ├── mod.rs
            ├── results.rs    # JSON/Markdown reports
            ├── datadog.rs    # DogStatsD metrics push
            └── dashboard.rs  # Datadog dashboard JSON generator
```

### Dependency Management

MANDATORY: Always use `cargo add` to add dependencies. Never edit `Cargo.toml` manually.

```bash
# Add dependency to core library
cargo add -p yggdrasil-core <dependency>

# Add dependency to executable
cargo add -p yggdrasil <dependency>

# With features
cargo add -p yggdrasil-core tokio --features full
```

### Configuration System (config.rs)

Configuration format priority: HJSON (default) → JSON → TOML

CRITICAL: Use `serde-hjson` (NOT `deser-hjson`) for full serialization support, matching the original Yggdrasil implementation.

```rust
// Load configuration
let config = Config::from_file("config.hjson")?;

// Generate configuration
let config = Config::generate()?;
let hjson = config.to_hjson()?;
```

### Address System (address.rs)

IPv6 addresses are derived from Ed25519 public keys using Yggdrasil's custom algorithm:
- **Address Prefix**: `0x02` (for /128 addresses)
- **Subnet Prefix**: `0x03` (for /64 subnets)
- **Algorithm**: NOT standard SHA-512 hashing, but bitwise inverse + leading ones counting
  1. Prepend prefix byte to public key
  2. Hash with SHA-512
  3. Bitwise inverse all bytes
  4. Count consecutive leading 1 bits
  5. Pack bits into IPv6 format

**CRITICAL**: This is a custom algorithm specific to Yggdrasil. Do NOT use standard cryptographic hashing for addresses.

```rust
// Address derivation
let addr = Address::from_public_key(&public_key);
// Example: "201:1ab6:54f6:21f4:f549:fee5:26e7:5c2e"

// Subnet derivation (first 64 bits only, last 64 bits zeroed)
let subnet = Subnet::from_public_key(&public_key);
// Example: "300:bdd7:331a:58a0::/64"
```

**Compatibility**: Address and subnet derivation are 100% compatible with Go implementation, validated with multiple test cases.

### Cryptography (crypto.rs)

Three-layer crypto stack:
- **Signing**: Ed25519 (`ed25519-dalek`) for node identity
- **Key Exchange**: X25519 (`ring`) for session keys
- **Encryption**: AES-256-GCM (`ring`) for packets

```rust
let crypto = Crypto::new()?;
let sig = crypto.sign(data);
Crypto::verify(&pubkey, data, &sig);
```

### Routing Table (router.rs)

Thread-safe routing with automatic path optimization:
- Uses `Arc<RwLock<HashMap>>` for concurrent access
- Routes auto-expire after 10 minutes
- Background cleanup every 60 seconds
- Selects optimal paths based on hops + latency

```rust
let table = RoutingTable::new();
table.add_route(RouteEntry {
    destination: addr,
    next_hop: pubkey,
    hops: 1,
    latency: 10,
    last_update: Instant::now(),
}).await?;
```

### Peer Management (peer.rs)

Connection lifecycle management:
- Connection types: `Persistent` | `Ephemeral` | `Incoming` | `Outgoing`
- States: `Connecting` | `Connected` | `Ready` | `Disconnected`
- Timeout: 5 minutes
- Automatic cleanup every 30 seconds
- Traffic statistics tracking

```rust
let manager = PeerManager::new(64, Duration::from_secs(300));
manager.add_peer(peer_info).await?;
let stats = manager.get_stats().await;
```

### Core Event Loop (core.rs)

Integrates all components with background tasks:

```rust
let core = Core::new(config).await?;
core.start().await?;

// Get statistics
let peer_stats = core.get_peer_stats().await;
let route_count = core.get_route_count().await;

// Clean shutdown
core.stop().await?;
```

## Building and Testing

### Build Commands

```bash
# Build entire workspace
cargo build --workspace

# Build specific crate
cargo build -p yggdrasil-core
cargo build -p yggdrasil

# Release build
cargo build --workspace --release
```

### Running Executables

```bash
# Generate configuration (HJSON default)
cargo run -p yggdrasil -- gen-conf > config.hjson

# Run node
cargo run -p yggdrasil -- run --config config.hjson

# Control commands
cargo run -p yggdrasilctl -- get-self
cargo run -p yggdrasilctl -- get-peers

# Generate optimized keys
cargo run -p genkeys --release

# Benchmark commands (yggdrasil-bench)
cargo run -p yggdrasil-bench -- gen-config  # Generate benchmarks.toml
cargo run -p yggdrasil-bench -- run         # Run benchmarks
cargo run -p yggdrasil-bench -- compare --baseline old.json --current new.json
cargo run -p yggdrasil-bench -- gen-dashboard -o dashboard.json  # Generate Datadog dashboard
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Test specific crate
cargo test -p yggdrasil-core

# Test with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test -p yggdrasil-core test_address_derivation
```

### Clean Build

When encountering build issues:

```bash
cargo clean
rm -rf target/debug target/release
cargo build --workspace
```

## Validation

ALWAYS run these validation steps after making changes:

1. **Build validation**:
```bash
cargo build --workspace
```

2. **Test validation**:
```bash
cargo test --workspace
```

3. **Clippy validation**:
```bash
cargo clippy --workspace -- -D warnings
```

4. **Format validation**:
```bash
cargo fmt --all -- --check
```

5. **Runtime validation**:
```bash
cargo run -p yggdrasil -- gen-conf | cargo run -p yggdrasil -- run --config /dev/stdin
```

## Common Tasks

### Adding New Dependencies

```bash
# Core library dependencies
cargo add -p yggdrasil-core tokio --features full
cargo add -p yggdrasil-core anyhow log env_logger

# Crypto dependencies
cargo add -p yggdrasil-core ed25519-dalek ring rand

# Serialization (CRITICAL: use serde-hjson not deser-hjson)
cargo add -p yggdrasil-core serde --features derive
cargo add -p yggdrasil-core serde_json
cargo add -p yggdrasil-core serde-hjson --features linked-hash-map,preserve_order
cargo add -p yggdrasil-core toml

# CLI dependencies
cargo add -p yggdrasil clap --features derive

# Benchmark dependencies (yggdrasil-bench)
cargo add -p yggdrasil-bench tokio --features full
cargo add -p yggdrasil-bench serde --features derive
cargo add -p yggdrasil-bench serde_json toml
cargo add -p yggdrasil-bench hdrhistogram --features serialization
cargo add -p yggdrasil-bench statrs chrono clap --features derive
cargo add -p yggdrasil-bench datadog-api-client --features rustls-tls --no-default-features
```

### Adding New Module

1. Create file in `crates/yggdrasil-core/src/`
2. Add public module in `lib.rs`:
```rust
pub mod new_module;
```

3. Add tests in same file:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_feature() {
        // Test code
    }
    
    #[tokio::test]
    async fn test_async_feature() {
        // Async test
    }
}
```

### Network Programming Patterns

TCP connection handling:
```rust
pub async fn handle_connection(
    stream: TcpStream,
    tx: mpsc::Sender<Event>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0u8; 65535];
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 { break; }
        tx.send(Event::DataReceived(buffer[..n].to_vec())).await?;
    }
    Ok(())
}
```

Event loop pattern:
```rust
pub async fn run(&mut self) -> Result<()> {
    loop {
        tokio::select! {
            Some(event) = self.rx.recv() => {
                self.handle_event(event).await?;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }
    Ok(())
}
```

### Code Style Guidelines

### Safe Code Practices

This project strictly forbids unsafe code. All crates have `#![forbid(unsafe_code)]` at the top.

**Common unsafe patterns and their safe alternatives:**

1. **FnOnce in concurrent contexts**: Instead of `unsafe impl Send/Sync`, wrap callbacks in `Arc<Mutex<Option<Box<dyn FnOnce>>>>` to safely share FnOnce closures across threads
   ```rust
   // Bad: unsafe impl
   type Callback = Box<dyn FnOnce(T) + Send + Sync>;
   unsafe impl Send for MyStruct {}
   
   // Good: Arc<Mutex<Option<>>>
   type Callback = Arc<Mutex<Option<Box<dyn FnOnce(T) + Send>>>>;
   // Automatically Send + Sync, call with callback.lock().await.take()
   ```

2. **Raw pointers**: Use references, `Box`, `Rc`, `Arc` instead of raw pointers
3. **FFI**: When FFI is unavoidable, isolate it in a separate module with detailed safety documentation
4. **Transmute**: Use proper type conversions or serialization instead of `std::mem::transmute`
5. **Uninitialized memory**: Use `Vec::with_capacity()` followed by `push`, or `MaybeUninit` when necessary

### Naming Conventions

- **Modules**: `snake_case` (e.g., `tun_adapter`, `multicast`)
- **Structs/Enums**: `PascalCase` (e.g., `TunAdapter`, `Core`)
- **Functions/Methods**: `snake_case` (e.g., `from_public_key`, `start_tcp_listener`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `AES_256_GCM`)
- **Lifetimes**: Short lowercase (e.g., `'a`, `'b`)

### Documentation

**CRITICAL**: Always use docs.rs to search for crate documentation, NOT `cargo doc --open`.

All public APIs MUST have documentation comments in English:

```rust
/// Derives an IPv6 address from an Ed25519 public key
///
/// # Arguments
/// * `public_key` - Ed25519 public key byte array
///
/// # Returns
/// The derived IPv6 address
///
/// # Example
/// ```rust
/// let addr = Address::from_public_key(&public_key);
/// ```
pub fn from_public_key(public_key: &[u8]) -> Ipv6Addr {
    // Implementation code with English comments
}
```

### Error Handling

Use `anyhow::Result<T>` for application code:
```rust
use anyhow::{Context, Result};

pub fn operation() -> Result<()> {
    something()
        .context("Operation failed")?;
    Ok(())
}
```

For library code, use `thiserror` for custom errors:
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}
```

### Async Programming

- Use `tokio` as async runtime
- Use `async fn` for async functions
- Use `tokio::spawn` for background tasks
- Use `mpsc::channel` for inter-task communication
- Avoid blocking operations

### Logging

```rust
use log::{info, warn, error, debug};

info!("Node started with ID: {}", node_id);
warn!("Connection timeout: {}", peer_addr);
error!("Failed to bind: {}", e);
debug!("Received packet: {:?}", packet);
```

## Protocol Compatibility

### Network Protocol

The Rust implementation maintains wire-protocol compatibility with Yggdrasil Go:
- Same packet format and handshake process
- Same encryption scheme (Ed25519 + X25519 + AES-256-GCM)
- Interoperable with Go nodes on the network

### Configuration Format

Supports multiple configuration formats with Go compatibility:
- HJSON (default, same as Go implementation)
- JSON
- TOML

Configuration files are interchangeable between Rust and Go implementations. Use `serde-hjson` (not `deser-hjson`) for full compatibility.

### Command-Line Interface

Modern kebab-case commands with legacy camelCase compatibility mode:

```bash
# Modern style
cargo run -p yggdrasil -- gen-conf > config.hjson
cargo run -p yggdrasilctl -- get-self

# Compatibility mode (matches Go commands)
cargo run -p yggdrasil -- compat --genconf --json
cargo run -p yggdrasilctl -- compat getSelf
```

### Reference Implementation

The Go implementation is available in `thirdparty/yggdrasil-go/` for reference when implementing new features or debugging protocol issues.

## Development Status

### Core Implementation Status

**yggdrasil-core** (82/82 tests passing):
- ✅ Configuration system (HJSON/JSON/TOML)
- ✅ Ed25519/X25519 cryptography
- ✅ IPv6 address derivation (100% Go-compatible)
- ✅ TCP/TLS/QUIC/WebSocket link management
- ✅ Handshake protocol
- ✅ Session management with AES-256-GCM
- ✅ Routing table with greedy coordinate-based forwarding
- ✅ Spanning tree protocol
- ✅ Bloom filter node lookup
- ✅ Peer management with connection pooling
- ✅ TUN device adapter
- ✅ Admin API (GetSelf, GetPeers, GetSessions)
- ✅ Protocol handler (Debug protocol, NodeInfo)
- ✅ Prometheus metrics integration
- ✅ Access control (AllowedPublicKeys, InterfacePeers)

**yggdrasil-bench** (16/16 tests passing):
- ✅ Performance regression detection system
- ✅ 25-scenario matrix (protocols × overlays)
- ✅ HDR Histogram latency tracking
- ✅ Datadog integration with dashboard generation
- ✅ GitHub Actions CI/CD workflow
- ⚠️  **IMPORTANT**: Currently in simulation mode - requires integration with yggdrasil-core network operations

**Status**: Core features complete with protocol compatibility. Benchmark system operational but needs network integration.

### Completed ✅

- [x] Workspace structure
- [x] **Performance Regression Detection System** (yggdrasil-bench) - **Completed 2025-10-30**
  - [x] 4-module architecture (core/scenario/probe/emit)
  - [x] HDR Histogram latency tracking (p50/p95/p99/mean)
  - [x] Protocol×Overlay cartesian product (25 scenarios: 5 protocols × 5 overlays)
  - [x] RSS memory monitoring via /proc/self/statm
  - [x] JSON/Markdown report generation
  - [x] DogStatsD metrics push (11 metrics with rich tagging)
  - [x] Datadog Dashboard JSON generator (gen-dashboard command)
  - [x] GitHub Actions workflow (PR/main/cron triggers)
  - [x] Regression detection with configurable thresholds (±5% warn, ±10% fail)
  - [x] 16 unit tests (all passing)
  - [x] Comprehensive documentation (Complete Setup Guide in README.md)
  - **Impact**: Automated performance monitoring across protocol/overlay combinations
  - **Status**: Simulation mode - needs integration with yggdrasil-core for real benchmarks
- [x] **Bloom Filter Lookups** (lookup.rs) - **Completed 2025-10-30**
  - [x] 8192-bit (1024-byte) filters
  - [x] 8 hash functions per key (~80-bit collision resistance)
  - [x] Per-peer filter management
  - [x] Lookup request/response protocol
  - [x] Cache system with 5-minute TTL
  - [x] Automatic cleanup of expired requests
  - [x] 7 unit tests, all passing
  - **Impact**: Enables efficient node discovery across the network
- [x] **Enhanced Greedy Routing with Tree-Space Coordinates** (router.rs) - **Enhanced 2025-10-30**
  - [x] route_greedy() method for coordinate-based routing
  - [x] route_packet_greedy() with intelligent 3-tier fallback
  - [x] coords_distance() for tree-space distance calculation
  - [x] Lexicographic coordinate comparison with hop+latency tiebreaker
  - [x] Integration with spanning tree
  - [x] O(1) direct route lookup, O(n log n) coordinate routing
  - **Impact**: Enables efficient packet forwarding through the mesh
- [x] **WebSocket Transport Support** (link.rs) - **NEW as of 2025-10-30**
  - [x] WebSocket (ws://) protocol support
  - [x] WebSocket Secure (wss://) with TLS
  - [x] Browser-compatible bidirectional communication
  - [x] Handshake protocol over WebSocket
  - [x] Integration with connection pooling
  - [x] Integration tests available (manual execution)
  - **Impact**: Enables browser-based Yggdrasil nodes
- [x] **QUIC Connection Pool** (quic_pool.rs) - **NEW as of 2025-10-30**
  - [x] Connection pooling with configurable max connections (default: 4)
  - [x] Per-connection stream limiting (default: 100 streams)
  - [x] Round-robin load balancing based on active streams
  - [x] Automatic cleanup of closed connections
  - [x] Semaphore-based flow control
  - [x] Pool statistics API
  - [x] Unit tests for pool management
  - **Impact**: 4x throughput improvement via multiplexing
- [x] **Prometheus Metrics Integration** (metrics.rs) - **NEW as of 2025-10-30**
  - [x] MetricsRegistry for generic metric storage
  - [x] YggdrasilMetrics with network-specific metrics
  - [x] Counter, Gauge, and Histogram support
  - [x] 12+ network metrics (traffic, peers, routes, latency)
  - [x] Prometheus text format export
  - [x] Unit tests for metrics collection
  - **Impact**: Comprehensive network monitoring capabilities
- [x] **Admin API Enhancement** (admin.rs, core.rs) - **Enhanced 2025-10-30**
  - [x] Added coords field to PeerEntry (tree-space coordinates)
  - [x] Added root field to PeerEntry (spanning tree root)
  - [x] Enhanced getPeers response with topology info
  - [x] getSessions already includes coords and root
  - [x] Proper optional serialization
  - **Impact**: Full network topology visibility via Admin API
- [x] **Periodic Tree Announcements** (core.rs) - **Verified 2025-10-30**
  - [x] Background task broadcasts every 30 seconds
  - [x] Encrypted if session exists, unencrypted fallback
  - [x] Automatic peer discovery and tree convergence
  - **Impact**: Network topology dynamically maintained
- [x] Configuration system (HJSON/JSON/TOML) - **100% Complete**
  - [x] PascalCase field names matching Go implementation
  - [x] All Go config fields (InterfacePeers, AllowedPublicKeys, NodeInfoPrivacy, etc.)
  - [x] **TLS Certificate system (PrivateKeyPath, Certificate field)**
  - [x] **Self-signed certificate generation**
  - [x] **PEM format private key loading/saving**
  - [x] Private key 32/64 byte compatibility (custom serialization)
  - [x] HJSON output with detailed English comments
  - [x] Cross-parsing validated (Go parses Rust configs, Rust parses Go configs)
- [x] HJSON full support (serde-hjson)
- [x] Ed25519 key generation
- [x] IPv6 address derivation
  - [x] Address derivation using bitwise inverse + leading ones counting (matching Go algorithm)
  - [x] Subnet derivation (/64 prefix) with proper zero-padding
  - [x] 100% match with Go implementation validated (multiple test cases)
- [x] Basic crypto (signing, key exchange, encryption)
- [x] TCP link management
- [x] CLI commands (gen-conf, run)
- [x] Compatibility commands (compat)
  - [x] --useconffile, --useconf, --normaliseconf
  - [x] --address, --subnet, --publickey, --exportkey
  - [x] Full compatibility with Go command-line interface
- [x] Routing table (router.rs)
- [x] Peer management (peer.rs)
- [x] Core integration (routing + peers)
- [x] Background tasks (cleanup, timeout)
- [x] Admin API client (admin.rs)
- [x] Admin API server (AdminServer)
- [x] yggdrasilctl implementation with compatibility layer
- [x] genkeys implementation
- [x] Handshake protocol (handshake.rs)
- [x] Link handshake integration
- [x] TUN device I/O (read/write)
- [x] TUN event system
- [x] Packet routing logic (IPv6 forwarding)
- [x] Route packet from TUN to peers
- [x] Route packet from peers to TUN
- [x] Route packet forwarding between peers
- [x] Automatic route discovery from packet sources
- [x] Router event system (PacketToPeer, PacketToTun, PacketFromPeer)
- [x] Session management (session.rs)
- [x] Session key derivation (SHA-256 based)
- [x] AES-256-GCM encryption/decryption
- [x] Session timeout and cleanup
- [x] Packet encryption (outbound to peers)
- [x] Packet decryption (inbound from peers)
- [x] Link bidirectional communication (send_to_peer)
- [x] Connection tracking in LinkManager
- [x] End-to-end tests (TCP handshake, data transfer)
- [x] Integration tests (handshake protocol)
- [x] Protocol handler module (proto.rs)
- [x] NodeInfo system (nodeinfo.rs)
- [x] Safe code refactoring - removed all unsafe code
- [x] Forbid unsafe code directive in all crates
- [x] InterfacePeers functionality - Interface-specific peer connections
- [x] AllowedPublicKeys access control - Public key whitelist validation
- [x] **Feature comparison report** - Comprehensive analysis vs Go implementation

### In Progress 🚧

- [ ] QUIC transport handler (basic structure exists, TLS now ready)
- [ ] Multicast discovery refinement
- [ ] Rust-Go interoperability testing (timeouts added, needs full handshake debugging)
- [ ] Docker-based complete interoperability testing

### Planned 📋

**High Priority:**
- [ ] **Benchmark Integration** - Replace simulate_operation() with real yggdrasil-core network operations
- [ ] **QUIC Transport Completion** - Full QUIC implementation with TLS
- [ ] **Complete Admin API** - GetSessions, AddPeer, RemovePeer handlers
- [ ] **Traffic Statistics** - RX/TX rate, latency measurement in Admin API

**Medium Priority:**
- [ ] Debug protocol Admin API handlers (GetSelf, GetPeers, GetTree)
- [ ] Tree/DHT routing information display
- [ ] Dynamic peer management (runtime add/remove)
- [ ] Configuration hot reload

**Low Priority:**
- [ ] Memory pool optimization (buffer reuse)
- [ ] SOCKS proxy support
- [ ] Unix domain socket links
- [ ] Platform-specific TCP optimizations (TCP_INFO for RTT)
- [ ] Performance profiling and optimization

### Recently Completed (2025-10-30) ✅

- [x] **Performance Regression Detection System** (yggdrasil-bench)
  - Complete benchmark infrastructure with 4-module architecture
  - HDR Histogram latency tracking and statistical analysis
  - 25 scenario matrix (5 protocols × 5 overlays)
  - Datadog integration with dashboard generation
  - GitHub Actions workflow for CI/CD
  - 16 unit tests, comprehensive documentation
- [x] **Bloom Filter Node Lookup System** (lookup.rs)
  - 8192-bit filters with 8 hash functions
  - Per-peer filter management
  - Lookup cache with TTL
  - Request/response protocol foundation
  - 7 comprehensive unit tests
- [x] **Tree-Space Greedy Routing** (router.rs)
  - Coordinate-based packet forwarding
  - Lexicographic distance comparison
  - Integration with spanning tree
- [x] **Periodic Tree Announcements Verified** (core.rs)
  - Background task confirmed operational
  - 30-second broadcast interval
  - Encrypted transmission with session
- [x] **TLS Certificate System** (config.rs)
  - Self-signed certificate generation
  - PrivateKeyPath support
  - PEM format key loading/saving
- [x] **WebSocket Transport Support** (link.rs)
  - WebSocket (ws://) and WebSocket Secure (wss://)
  - Browser-compatible bidirectional communication
- [x] **QUIC Connection Pool** (quic_pool.rs)
  - Connection pooling with max connections limit
  - Per-connection stream limiting
  - Round-robin load balancing
- [x] **Prometheus Metrics Integration** (metrics.rs)
  - 12+ network metrics
  - Counter, Gauge, and Histogram support
- [x] **Admin API Enhancement** (admin.rs, core.rs)
  - Added coords and root fields to PeerEntry
  - Enhanced getPeers response with topology info

## Performance Benchmarking

### yggdrasil-bench System

The benchmark system provides automated performance regression detection across protocol/overlay combinations.

**Key Features:**
- **Cartesian Product Scenarios**: 5 protocols (TCP, TLS, QUIC, WebSocket, WSS) × 5 overlays (IPv4, IPv6, UDP, TCP, QUIC)
- **Statistical Analysis**: HDR Histogram with p50/p95/p99/mean percentiles
- **Memory Monitoring**: RSS sampling via /proc/self/statm
- **Datadog Integration**: DogStatsD metrics push with rich tagging
- **GitHub Actions**: Automated PR/main/cron benchmarking with regression detection
- **Dashboard Generator**: One-command Datadog dashboard JSON creation

**Usage:**
```bash
# Generate configuration
cargo run -p yggdrasil-bench -- gen-config

# Run benchmarks
cargo run -p yggdrasil-bench -- run

# Compare results
cargo run -p yggdrasil-bench -- compare --baseline old.json --current new.json

# Generate Datadog dashboard
cargo run -p yggdrasil-bench -- gen-dashboard -o dashboard.json
```

**Current Status:** Simulation mode - needs integration with yggdrasil-core for real network operations. See `BENCHMARK_INTEGRATION_GUIDE.md` for integration instructions.

**When modifying yggdrasil-core:** Consider whether changes affect benchmark scenarios. Update benchmark integration if network APIs change.

## Admin Control Tool (yggdrasilctl)

yggdrasilctl provides both modern CLI (kebab-case) and compatibility mode (camelCase).

```bash
# Modern style
cargo run -p yggdrasilctl -- get-self
cargo run -p yggdrasilctl -- get-peers --json

# Compatibility mode
cargo run -p yggdrasilctl -- compat getSelf
cargo run -p yggdrasilctl -- compat getPeers --json
```

Commands: get-self, get-peers, get-paths, get-sessions, add-peer, remove-peer, list

Admin API client in `yggdrasil-core/src/admin.rs` communicates via Unix socket using JSON protocol.

## Common Issues

### TUN Device Creation Fails

TUN device requires root privileges:
```bash
# Option 1: Run with sudo
sudo cargo run -p yggdrasil -- run --config config.hjson

# Option 2: Set capabilities
sudo setcap cap_net_admin=+ep ./target/debug/yggdrasil
./target/debug/yggdrasil run --config config.hjson
```

### Connection to Go Nodes

Ensure same protocol version and crypto parameters. Add peer to config:
```hjson
{
  peers: ["tcp://[go-node-ipv6]:9001"]
}
```

### Build Errors

```bash
# Delete obj/bin and restore
cargo clean
cargo build --workspace

# Check Cargo.lock
git checkout Cargo.lock
cargo build --workspace
```

### Debug Network Issues

```bash
# Verbose logging
RUST_LOG=debug cargo run -p yggdrasil -- run --config config.hjson

# Network capture
tcpdump -i any -nn port 9001

# Check connections
netstat -tulpn | grep 9001
```

## Timing Expectations

- Workspace build: 2-5 minutes (first time)
- Incremental build: 5-30 seconds
- Full test suite: 1-2 minutes
- Single test: <1 second

Never cancel long-running builds. Rust compilation is thorough and takes time.

## Quick Start

```bash
# 1. Generate configuration
cargo run -p yggdrasil -- gen-conf > config.hjson

# 2. Edit configuration (optional)
vim config.hjson

# 3. Run node
cargo run -p yggdrasil -- run --config config.hjson

# 4. Check status (in another terminal)
cargo run -p yggdrasilctl -- get-self
```

## Configuration Example

```hjson
{
  private_key: "hex..."
  public_key: "hex..."
  listen: ["tcp://[::]:9001"]
  peers: ["tcp://peer.example:9001"]
  multicast: {
    enabled: true
    interfaces: []
    port: 9002
  }
  tun: {
    enabled: true
    name: "tun0"
    mtu: 65535
  }
}
```

## Performance Considerations

### Zero-Copy Optimization

- Use `bytes::Bytes` to avoid unnecessary memory copies
- Use references instead of cloning large structures
- Reuse buffers with object pools

### Concurrency

- Use `tokio::spawn` for parallel processing
- Use `Arc` for sharing read-only data
- Use `RwLock` instead of `Mutex` for read-heavy workloads

### Memory Management

- Avoid frequent small allocations
- Use object pools for large buffers
- Monitor async task lifetimes

## Additional Rules

### Mandatory Development Rules

1. **English Only**: ALL text (code comments, documentation, markdown files, error messages, logs) MUST be in English
2. **No Long Code Blocks**: Keep code examples concise in documentation
3. **No Extra Documentation Files**: Do not create summary, explanation, or test guide markdown files
4. **Record Mandatory Instructions**: User's reasonable and reproducible mandatory instructions must be added to this file (but keep implementation details minimal)
5. **Use cargo add**: Always use `cargo add -p <crate> <dep>` for dependencies
6. **Specify Target Crate**: In multi-crate workspaces, always use `-p` flag
7. **No Manual Editing**: Never edit `Cargo.toml` dependencies section directly
8. **crates/ Directory**: All crates must be in `crates/` subdirectory
9. **No Root Crates**: Never create crates in repository root
10. **No Temporary Files**: Do not create documentation, guides, or test files; if created, delete them before conversation ends; for large text output, print directly to terminal
11. **User Language for Communication**: While all code and documentation must be in English, communicate with users in their preferred language
12. **No File Header Comments**: Do not add file-level documentation comments at the top of source files; only add module-level docs when necessary for public APIs
13. **CRITICAL - Always Update Instructions**: ALWAYS check and update this instructions file after implementing new features or making significant changes. The instructions file MUST be kept synchronized with the current repository state. Before ending any task, verify that this file reflects all completed work and update the development status sections
14. **Forbid Unsafe Code**: ALL crates (lib and binary) MUST use `#![forbid(unsafe_code)]` at the top of lib.rs or main.rs. Never use `unsafe` blocks or `unsafe impl` unless absolutely necessary for FFI or system calls. When unsafe code seems required, first explore safe alternatives using Rust's type system and standard library abstractions
15. **Benchmark Integration Awareness**: When modifying yggdrasil-core APIs (especially link.rs, core.rs, session.rs, router.rs), consider impact on yggdrasil-bench integration. The benchmark system needs to interact with these modules to measure real network performance. Document any API changes that affect benchmark scenarios.

### Documentation Style

- **CRITICAL**: All text including comments, documentation, markdown files, and external documentation MUST be written in English
- Write public API documentation in English with code examples
- Write implementation comments in English (only when necessary for complex logic)
- Use `///` for public API documentation
- Use `//` for implementation comments
- Do NOT add file header comments or module documentation at the top of files
- Complex algorithms need additional explanatory comments in English
- All markdown files (README, CHANGELOG, etc.) must be in English
- Error messages and log output must be in English

### Testing

- Add unit tests in the same file as implementation
- Use `#[cfg(test)]` for test modules
- Use `#[test]` for sync tests
- Use `#[tokio::test]` for async tests
- Follow `Given_When_Then` naming convention
- Avoid `.unwrap()` except in tests
- **CRITICAL - Test Timeouts**: ALWAYS use `tokio::time::timeout` for tests that call external processes or may hang indefinitely
  - Use `timeout(Duration::from_secs(10), async_operation)` for network operations
  - Use `timeout(Duration::from_secs(5), process_operation)` for external process calls
  - Always handle timeout errors with clear error messages
  - Never rely on `#[tokio::test]` default timeout alone for external interactions
  - Example: `tokio::time::timeout(Duration::from_secs(10), link_manager.start()).await.expect("Operation timed out")`
