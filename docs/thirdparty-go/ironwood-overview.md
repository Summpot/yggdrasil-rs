# Ironwood Library Overview

## Overview
Ironwood is the underlying routing library used by Yggdrasil. It provides the core networking primitives, routing algorithms, and cryptographic session management.

---

## Architecture

Ironwood is organized into several packages:

### types/ - Core Interfaces and Types
- **addr.go** - `Addr` type wrapping ed25519.PublicKey as net.Addr
- **packetconn.go** - `PacketConn` interface (extends net.PacketConn)
- **errors.go** - Error definitions
- **error_string.go** - String-based error type

#### Key Interfaces

##### `PacketConn`
Extends `net.PacketConn` with Yggdrasil-specific functionality:
- `HandleConn(key ed25519.PublicKey, conn net.Conn, prio uint8) error` - Handles peer connection
- `IsClosed() bool` - Non-blocking closed check
- `PrivateKey() ed25519.PrivateKey` - Returns node's private key
- `MTU() uint64` - Returns maximum transmission unit
- `SendLookup(target ed25519.PublicKey)` - Initiates DHT key lookup

##### `Addr`
Implements `net.Addr` for ed25519 public keys:
- `Network() string` - Returns "ed25519.PublicKey"
- `String() string` - Returns hex-encoded public key

### network/ - Core Routing Layer
Main routing implementation with several components:

#### Core Components
- **core.go** - Main core structure coordinating all subsystems
- **config.go** - Configuration options
- **packetconn.go** - PacketConn implementation
- **router.go** - Routing logic and next-hop decisions
- **peers.go** - Peer connection management
- **pathfinder.go** - Path discovery and tree building
- **crypto.go** - Cryptographic operations (sign/verify)
- **wire.go** - Wire protocol for network packets

#### Traffic Management
- **traffic.go** - Traffic statistics and flow control
- **packetqueue.go** - Packet buffering and prioritization
- **pool.go** - Memory pool for packet buffers

#### Utilities
- **debug.go** - Debugging helpers
- **bloomfilter.go** - Bloom filter for duplicate detection

#### Data Structures

##### `core`
Central coordinator:
- `config: config` - Network configuration
- `crypto: crypto` - Cryptographic primitives
- `router: router` - Routing table and logic
- `peers: peers` - Peer management
- `pconn: PacketConn` - Packet interface

Initialization: `init(secret ed25519.PrivateKey, opts ...Option)`

### encrypted/ - Encrypted Session Layer
Provides encrypted end-to-end sessions on top of routing layer:

- **packetconn.go** - Encrypted PacketConn implementation
- **session.go** - Session management (handshake, keys)
- **crypto.go** - Session encryption/decryption
- **network.go** - Network-level session handling
- **pool.go** - Buffer pooling for encrypted packets
- **debug.go** - Debug logging
- **internal/e2c/** - End-to-end crypto primitives

#### Key Features
- End-to-end encryption between nodes
- Session key negotiation
- Forward secrecy
- Replay protection

### signed/ - Signed Packet Layer
Adds signature verification layer:

- **packetconn.go** - Signed PacketConn wrapper

#### Purpose
- Verifies packet authenticity
- Prevents spoofing
- Adds ed25519 signatures to packets

---

## Routing Algorithm

### Greedy Routing
Ironwood uses **greedy routing** based on ed25519 public keys:
1. Each node has an ed25519 public key as its address
2. Routing decisions based on key distance (XOR metric)
3. Packets forwarded to peer closest to destination key
4. Tree structure built for efficient routing

### Path Discovery
- **Bootstrap**: Connects to known peers
- **Tree Building**: Constructs spanning tree of network
- **Pathfinding**: Uses tree to route packets
- **Key Lookup**: DHT-like lookup for unknown keys

### Peer Management
- Maintains set of active peer connections
- Monitors peer health (traffic, latency)
- Prunes dead peers
- Adds new peers from discovery

---

## Packet Flow

### Outbound
1. Application writes to PacketConn
2. Router determines next hop
3. Encrypts for session (if encrypted layer)
4. Signs packet (if signed layer)
5. Sends to peer

### Inbound
1. Receives from peer connection
2. Verifies signature (if signed layer)
3. Decrypts session (if encrypted layer)
4. Routes to application or forwards

---

## Configuration

### Options (network/config.go)
- Routing algorithm parameters
- Buffer sizes
- Timeout values
- Debug settings

Can be customized via functional options pattern.

---

## Comparison with yggdrasil-rs

### Expected Implementation Status

**Routing (`yggdrasil-routing` crate):**
- Core routing logic should be implemented
- Path discovery and tree building
- Peer management
- Greedy routing algorithm

**Session (`yggdrasil-session` crate):**
- Encrypted sessions
- Key negotiation
- Session management

**Wire Protocol (`yggdrasil-wire` crate):**
- Packet serialization/deserialization
- Protocol constants
- Message types

### Critical Components

1. **Routing Algorithm** - Core of network
2. **Session Encryption** - End-to-end security
3. **Peer Management** - Connection handling
4. **Pathfinding** - Network discovery

### Priority

- **CRITICAL**: Core routing (network/)
- **CRITICAL**: Encrypted sessions (encrypted/)
- **HIGH**: Packet formats (types/)
- **MEDIUM**: Signed packets (signed/)

---

## Key Differences from Traditional Routing

### Traditional IP Routing
- Hierarchical addresses (CIDR blocks)
- Routing tables with prefix matching
- BGP for inter-AS routing

### Ironwood/Yggdrasil Routing
- Flat address space (ed25519 keys)
- Greedy routing to closest key
- Self-organizing network topology
- No central routing authority

### Advantages
- Automatic network formation
- Resilient to topology changes
- No address allocation needed
- End-to-end encryption built-in

### Challenges
- Route stretch (paths may not be optimal)
- DHT lookup overhead
- Relies on good peer selection

---

## Integration Notes

### For Rust Implementation

1. **Cryptography**: Use `ed25519-dalek` for keys and signatures
2. **Networking**: Use `tokio` for async I/O
3. **Routing State**: Efficient data structures (hash maps, trees)
4. **Packet Buffers**: Consider using `bytes` crate
5. **Sessions**: State machine for handshake and encryption

### Testing Considerations

- Interoperability with Go implementation is critical
- Wire format must match exactly
- Routing algorithm behavior must be identical
- Encryption/signatures must be compatible

---

## Summary

Ironwood provides:
- **Overlay routing** based on public keys
- **Session layer** with end-to-end encryption
- **Packet interface** compatible with net.PacketConn
- **Self-organizing** network topology
- **DHT-like** key lookups

It's the foundation that Yggdrasil builds upon to create a complete mesh network solution.

### Files Analyzed
- types/addr.go - Address type
- types/packetconn.go - PacketConn interface
- network/core.go - Core structure

### Files Pending (30+ files)
- Detailed analysis of routing algorithms
- Session management internals
- Crypto implementation details
- Wire protocol formats
- Pathfinding algorithms
- Bloom filter usage
- Traffic management

**Note**: Ironwood is a large subsystem. Full analysis would require deep dive into routing algorithms, which is beyond initial scope. Focus on interfaces and integration points with Yggdrasil.
