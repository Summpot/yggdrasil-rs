# Protocol Integration Guide

This guide explains how to integrate additional transport protocols into the yggdrasil-rs Links manager.

## Current Architecture

The `Links` manager in `crates/yggdrasil-link/src/links.rs` currently supports TLS connections exclusively. The manager handles:

1. **Connection lifecycle**: Establishing, maintaining, and closing peer connections
2. **Peer handshake**: Yggdrasil protocol version negotiation and authentication
3. **Event management**: Broadcasting connection events and peer state changes
4. **Metrics tracking**: RX/TX bytes, connection status, uptime

## Protocol Support Status

### Fully Integrated
- **TLS (tls://)**: Complete integration with handshake, peer handler, and metrics

### Module Complete, Not Integrated
- **TCP (tcp://)**: Module in `tcp.rs` implements `Link` trait
- **QUIC (quic://)**: Module in `quic.rs` implements `Link` trait
- **Unix Sockets (unix://)**: Module in `unix.rs` implements `Link` trait (Unix only)
- **WebSocket (ws://, wss://)**: Module in `websocket.rs` implements `Link` trait

### Missing
- **SOCKS5 (socks://, sockstls://)**: No implementation yet

## Integration Requirements

To integrate a new protocol, you need to:

### 1. Implement the `Link` Trait

All protocols must implement the `Link` trait from `link.rs`:

```rust
#[async_trait]
pub trait Link: Send + Sync {
    fn info(&self) -> &LinkInfo;
    async fn send(&self, data: &[u8]) -> Result<(), LinkError>;
    async fn recv(&self) -> Result<Vec<u8>, LinkError>;
    async fn close(&self) -> Result<(), LinkError>;
    fn is_connected(&self) -> bool;
}
```

✅ **Status**: All existing protocol modules implement this trait correctly.

### 2. Connection Establishment

Each protocol needs a `connect` function that:
1. Establishes the transport-layer connection
2. Performs the Yggdrasil handshake
3. Returns the connected `Link` instance

**Example for TLS** (from `links.rs`):
```rust
pub async fn connect(
    &self,
    addr: SocketAddr,
    sintf: &str,
    link_type: LinkType,
    priority: u8,
    password: &[u8],
) -> Result<PublicKey, LinkError>
```

The function:
1. Connects via TCP
2. Wraps in TLS
3. Performs Yggdrasil handshake with `perform_handshake()`
4. Creates peer handler with metrics
5. Registers in Links map
6. Emits connection event

### 3. Listener Support

For server-side operation, implement:
```rust
pub async fn listen(
    &self,
    addr: SocketAddr,
    sintf: &str,
    password: &[u8],
) -> Result<u16, LinkError>
```

This should:
1. Bind to the specified address
2. Accept incoming connections
3. Perform handshakes
4. Create peer handlers
5. Register connections

## Refactoring Needed for Multi-Protocol Support

### Current Limitation

The `Links` manager is tightly coupled to TLS:
- Uses `TlsAcceptor` directly
- Stores TLS-specific configuration
- Connection logic hardcoded for TLS

### Proposed Architecture

#### Option A: Protocol-Specific Managers

Create protocol-specific managers that implement a common trait:

```rust
#[async_trait]
trait ProtocolManager {
    async fn connect(&self, uri: &str, options: ConnectOptions) -> Result<Box<dyn Link>, LinkError>;
    async fn listen(&self, uri: &str, options: ListenOptions) -> Result<Box<dyn Listener>, LinkError>;
}

struct TlsManager { /* ... */ }
struct WebSocketManager { /* ... */ }
struct TcpManager { /* ... */ }
```

Then the `Links` manager dispatches to the appropriate manager based on URI scheme.

#### Option B: Unified Connection Handler

Refactor `Links` to be protocol-agnostic:

```rust
enum Transport {
    Tls(TlsStream),
    Tcp(TcpStream),
    WebSocket(WebSocketStream),
    Quic(QuicConnection),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Transport {
    async fn perform_handshake(&mut self, ...) -> Result<Metadata, LinkError> {
        // Generic handshake that works over any transport
    }
}
```

## Minimal Integration Example

Here's how to add WebSocket support with minimal changes:

### Step 1: Add WebSocket Connect Function

```rust
pub async fn connect_websocket(
    &self,
    uri: &str,
    password: &[u8],
    link_type: LinkType,
    priority: u8,
) -> Result<PublicKey, LinkError> {
    // 1. Connect via WebSocket
    let ws_link = WebSocketLink::connect(uri, PublicKey::default(), LinkConfig::default()).await?;
    
    // 2. Perform Yggdrasil handshake
    // TODO: Need to adapt handshake to work with Link trait instead of TlsStream
    
    // 3. Create peer handler
    // 4. Register connection
    // 5. Emit event
    
    Ok(remote_key)
}
```

### Step 2: Update `connect_uri`

```rust
pub async fn connect_uri(&self, uri: &str, ...) -> Result<PublicKey, LinkError> {
    match protocol {
        "tls" => self.connect(socket, ...).await,
        "ws" | "wss" => self.connect_websocket(uri, ...).await,
        "tcp" => self.connect_tcp(socket, ...).await,
        "quic" => self.connect_quic(uri, ...).await,
        // ...
    }
}
```

### Step 3: Add WebSocket Listener

```rust
pub async fn listen_websocket(&self, addr: SocketAddr, ...) -> Result<u16, LinkError> {
    // Set up WebSocket server with warp or axum
    // Accept connections
    // Perform handshakes
    // Create peer handlers
}
```

## Handshake Adaptation

The current `perform_handshake` function works with `TlsStream`:

```rust
pub async fn perform_handshake<S>(
    stream: &mut S,
    private_key: &PrivateKey,
    priority: u8,
    password: &[u8],
) -> Result<VersionMetadata, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
```

✅ This already works with any `AsyncRead + AsyncWrite` stream, so it should work with WebSocket streams if we can adapt them.

**Challenge**: `tokio-tungstenite` uses `Message`-based API, not byte streams.

**Solution**: Create an adapter that wraps WebSocket in `AsyncRead/AsyncWrite`:

```rust
struct WebSocketAdapter {
    ws: WebSocketStream<...>,
    read_buf: BytesMut,
}

impl AsyncRead for WebSocketAdapter {
    fn poll_read(...) -> Poll<Result<usize>> {
        // Read from WebSocket Message::Binary
        // Buffer partial reads
    }
}

impl AsyncWrite for WebSocketAdapter {
    fn poll_write(...) -> Poll<Result<usize>> {
        // Write as WebSocket Message::Binary
    }
}
```

## WebSocket Server Integration

For incoming WebSocket connections:

```rust
use axum::{
    routing::get,
    extract::ws::{WebSocket, WebSocketUpgrade},
    Router,
};

async fn websocket_handler(
    ws: WebSocketUpgrade,
    // ... context ...
) -> Response {
    ws.protocols(["ygg-ws"])
        .on_upgrade(|socket| handle_websocket(socket))
}

async fn handle_websocket(socket: WebSocket) {
    // 1. Wrap socket in Link impl
    // 2. Perform handshake
    // 3. Create peer handler
    // 4. Register connection
}
```

## Testing New Protocols

### Unit Tests
Test each protocol module independently:

```rust
#[tokio::test]
async fn test_websocket_connect() {
    // Start WebSocket server
    // Connect via WebSocketLink
    // Verify handshake
    // Send/receive data
    // Close connection
}
```

### Integration Tests
Test full stack with real peers:

```rust
#[tokio::test]
async fn test_websocket_peer_connection() {
    // Start two nodes
    // One listens on ws://
    // Other connects
    // Verify peer handler starts
    // Verify traffic flows
}
```

## Priority Recommendations

### Immediate (Production Blocking)
**None** - TLS is fully functional and sufficient for production use.

### High Priority (User-Requested Features)
1. **WebSocket (ws://, wss://)** - Enables firewall traversal and browser support
   - Estimated effort: 2-3 days
   - Main task: Create WebSocketAdapter for AsyncRead/AsyncWrite
   - Main task: Implement WebSocket listener

### Medium Priority (Nice to Have)
2. **TCP (tcp://)** - Direct connections without TLS overhead
   - Estimated effort: 1 day
   - Simpler than WebSocket (already AsyncRead/AsyncWrite)

3. **QUIC (quic://)** - UDP-based, better for unreliable networks
   - Estimated effort: 2 days
   - Need to adapt quinn streams to AsyncRead/AsyncWrite

4. **Unix Sockets (unix://)** - Local IPC
   - Estimated effort: 0.5 days
   - Already AsyncRead/AsyncWrite compatible

### Low Priority (Edge Cases)
5. **SOCKS5 (socks://, sockstls://)** - Proxy support
   - Estimated effort: 3-4 days
   - Requires tokio-socks integration
   - Need to implement SOCKS5 client
   - Low real-world usage

## Conclusion

The current architecture supports TLS fully, which covers the primary use case. Additional protocols require:

1. **Protocol adapter layer** to unify different transport types
2. **Handshake abstraction** to work with both stream and message-based protocols
3. **Listener implementation** for each server-side protocol
4. **Testing infrastructure** to verify multi-protocol interoperability

**Estimated total effort for full multi-protocol support**: 1-2 weeks

**Recommended approach**: Start with WebSocket as it has the highest user value, then add others based on demand.
