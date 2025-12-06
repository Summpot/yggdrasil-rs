# Core: Link Protocols (unix, socks, ws, wss, quic)

## Overview
These files implement various link protocols for establishing peer connections over different transport mechanisms.

---

## link_unix.go

### Purpose
Unix domain socket transport for local peer connections.

### Data Structures

#### `linkUNIX`
- Extends `*links` (base link functionality)
- `dialer: *net.Dialer` - Connection dialer with 5s timeout
- `listener: *net.ListenConfig` - Socket listener configuration

### APIs

#### `(l *links) newLinkUNIX() *linkUNIX`
Creates new Unix socket link handler:
- Sets 5-second dial timeout
- Disables keep-alive (-1)

#### `(l *linkUNIX) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error)`
Establishes outbound Unix socket connection:
1. Resolves Unix address from URL path
2. Dials using context-aware dialer
3. Returns net.Conn

#### `(l *linkUNIX) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error)`
Creates Unix socket listener:
- Listens on URL path
- Returns net.Listener for accepting connections

### URL Format
```
unix:///path/to/socket
```

### Comparison with yggdrasil-rs
**Status:** Check if implemented
- Unix sockets are standard on Unix-like systems
- Rust: use `tokio::net::UnixListener` and `UnixStream`
- Check `yggdrasil-link` for Unix socket support
- Priority: MEDIUM (useful for local IPC)

---

## link_socks.go

### Purpose
SOCKS5 proxy transport for connecting through proxy servers.

### Data Structures

#### `linkSOCKS`
- Extends `*links` (base link functionality)
- No additional fields (uses TCP dialer)

### APIs

#### `(l *links) newLinkSOCKS() *linkSOCKS`
Creates new SOCKS link handler.

#### `(l *linkSOCKS) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error)`
Establishes connection through SOCKS5 proxy:
1. Extracts proxy authentication from URL (if present)
2. Resolves target IP addresses
3. Creates TCP dialer for proxy
4. Creates SOCKS5 proxy dialer using `golang.org/x/net/proxy`
5. Dials target through proxy
6. If scheme is `sockstls`, wraps connection in TLS:
   - Sets server name from hostname
   - TLS 1.2-1.3 only
   - Respects `tlsSNI` option for custom SNI

#### `(l *linkSOCKS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error)`
Returns error - SOCKS listener not supported (outbound-only).

### URL Format
```
socks://[user:pass@]proxy_host:port/target_host:port
sockstls://[user:pass@]proxy_host:port/target_host:port
```

### Comparison with yggdrasil-rs
**Status:** Likely NOT implemented
- SOCKS5 support requires proxy library
- Rust: use `tokio-socks` or similar crate
- Priority: LOW (advanced feature for proxy environments)

---

## link_ws.go

### Purpose
WebSocket transport for browser-compatible and firewall-friendly connections.

### Data Structures

#### `linkWS`
- Extends `*links`
- `listenconfig: *net.ListenConfig` - TCP listener config

#### `linkWSConn`
- Wraps `net.Conn` (WebSocket connection as net.Conn)

#### `linkWSListener`
- `ch: chan *linkWSConn` - Channel for accepted connections
- `ctx: context.Context` - Cancellation context
- `httpServer: *http.Server` - HTTP server for WebSocket upgrade
- `listener: net.Listener` - Underlying TCP listener

#### `wsServer`
- `ch: chan *linkWSConn` - Channel to send accepted WebSocket connections
- `ctx: context.Context` - Context for connection lifecycle

### APIs

#### HTTP Handler

##### `(s *wsServer) ServeHTTP(w http.ResponseWriter, r *http.Request)`
Handles HTTP requests:
- Health check endpoints: `/health` and `/healthz` return 200 OK
- WebSocket upgrade:
  - Requires `ygg-ws` subprotocol
  - Rejects non-compliant clients
  - Converts WebSocket to net.Conn using `MessageBinary` mode
  - Sends connection through channel

#### Link Operations

##### `(l *links) newLinkWS() *linkWS`
Creates new WebSocket link handler.

##### `(l *linkWS) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error)`
Establishes outbound WebSocket connection:
1. Resolves IP addresses from URL
2. Creates custom HTTP client with TCP dialer
3. Dials WebSocket with:
   - `ygg-ws` subprotocol
   - Proxy support via `http.ProxyFromEnvironment`
   - Custom Host header (for SNI)
4. Returns WebSocket as net.Conn

##### `(l *linkWS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error)`
Creates WebSocket listener:
1. Listens on TCP address
2. Starts HTTP server with WebSocket handler
3. Returns custom listener that reads from connection channel

##### Listener Methods
- `Accept() (net.Conn, error)` - Blocks on channel until connection arrives
- `Addr() net.Addr` - Returns underlying TCP listener address
- `Close() error` - Shuts down HTTP server and closes TCP listener

### URL Format
```
ws://hostname:port/path
```

### Features
- Binary WebSocket messages (`MessageBinary`)
- Health check endpoints for load balancers
- Subprotocol negotiation (`ygg-ws`)
- 10-second read/write timeouts

### Comparison with yggdrasil-rs
**Status:** Check implementation
- WebSocket support critical for browser/firewall traversal
- Rust: use `tokio-tungstenite` crate
- Check `yggdrasil-link` for WS support
- Priority: HIGH (important for network flexibility)

---

## link_wss.go

### Purpose
WebSocket Secure (WSS) - TLS-encrypted WebSocket transport.

### Data Structures

#### `linkWSS`
- Extends `*links`
- `tlsconfig: *tls.Config` - TLS configuration

#### `linkWSSConn`
- Wraps `net.Conn` (secure WebSocket connection)

### APIs

#### `(l *links) newLinkWSS() *linkWSS`
Creates new WSS link handler:
- Clones core TLS config

#### `(l *linkWSS) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error)`
Establishes outbound WSS connection:
1. Clones TLS config
2. Sets server name for TLS verification
3. Restricts to TLS 1.2-1.3
4. Resolves IP addresses
5. Creates HTTP client with TLS transport
6. Dials WebSocket with:
   - `ygg-ws` subprotocol
   - TLS client config
   - Proxy support
7. Returns secure WebSocket as net.Conn

#### `(l *linkWSS) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error)`
Returns error - WSS listener not supported.
**Note:** Recommends using WS listener behind reverse proxy (e.g., nginx) for TLS termination.

### URL Format
```
wss://hostname:port/path
```

### Comparison with yggdrasil-rs
**Status:** Check implementation
- WSS is WS + TLS
- Rust: same as WS but with TLS
- Outbound-only (listener via reverse proxy)
- Priority: HIGH (secure connections important)

---

## link_quic.go

### Purpose
QUIC transport for modern, multiplexed, UDP-based connections.

### Data Structures

#### `linkQUIC`
- Extends `*links`
- `tlsconfig: *tls.Config` - TLS 1.3 configuration (QUIC requires TLS 1.3)
- `quicconfig: *quic.Config` - QUIC-specific settings

#### `linkQUICStream`
- `*quic.Conn` - QUIC connection (can have multiple streams)
- `*quic.Stream` - Individual stream (like TCP connection)

#### `linkQUICListener`
- `*quic.Listener` - QUIC listener
- `ch: <-chan *linkQUICStream` - Channel for accepted streams

### APIs

#### `(l *links) newLinkQUIC() *linkQUIC`
Creates new QUIC link handler:
- Sets 1-minute max idle timeout
- 20-second keep-alive period
- Token store for 0-RTT (LRU cache, 255 entries)

#### `(l *linkQUIC) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error)`
Establishes outbound QUIC connection:
1. Clones TLS config
2. Sets server name
3. Restricts to TLS 1.2-1.3 (QUIC uses TLS 1.3)
4. Dials QUIC connection
5. Opens stream synchronously
6. Returns stream as net.Conn

#### `(l *linkQUIC) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error)`
Creates QUIC listener:
1. Listens on UDP address
2. Spawns goroutine to accept connections
3. For each connection, accepts stream
4. Sends stream through channel
5. Returns custom listener

#### Listener Goroutine
Handles connection and stream acceptance:
- Accepts QUIC connections
- For each connection, accepts first stream
- Handles cancellation and server close
- Closes connections with errors if stream acceptance fails

#### Listener Methods
- `Accept() (net.Conn, error)` - Blocks on channel until stream arrives

### URL Format
```
quic://hostname:port
```

### Features
- UDP-based (no need for TCP)
- Built-in encryption (TLS 1.3)
- Multiplexing (multiple streams per connection)
- 0-RTT support (token store)
- Connection migration support

### Comparison with yggdrasil-rs
**Status:** Likely NOT implemented
- QUIC is modern protocol, complex implementation
- Rust: use `quinn` crate (popular QUIC implementation)
- Priority: MEDIUM (modern, efficient, but not essential)

---

## Summary Table

| Protocol | Scheme | Listener | TLS | Priority | Notes |
|----------|--------|----------|-----|----------|-------|
| Unix | unix:// | ✓ | ✗ | Medium | Local IPC only |
| SOCKS5 | socks:// sockstls:// | ✗ | Optional | Low | Outbound through proxy |
| WebSocket | ws:// | ✓ | ✗ | High | Firewall-friendly |
| WebSocket Secure | wss:// | ✗* | ✓ | High | *Use WS + reverse proxy |
| QUIC | quic:// | ✓ | ✓ | Medium | Modern, UDP-based |

### Implemented in Go

1. **Unix sockets** - Local peer connections
2. **SOCKS5** - Proxy support with optional TLS
3. **WebSocket** - HTTP upgrade with health checks
4. **WSS** - TLS-secured WebSocket (outbound only)
5. **QUIC** - Modern UDP protocol with multiplexing

### Rust Implementation Status

- **Unix** - Check if implemented (straightforward)
- **SOCKS** - Likely not implemented (niche use case)
- **WebSocket** - Should be implemented (important)
- **WSS** - Should be implemented (important)
- **QUIC** - Likely not implemented (complex)

### Priority for Implementation

1. **HIGH**: WebSocket / WSS - Essential for firewall traversal
2. **MEDIUM**: Unix sockets - Useful for local connections
3. **MEDIUM**: QUIC - Modern, efficient, future-proof
4. **LOW**: SOCKS5 - Niche use case

### Integration Requirements

All link protocols must:
1. Implement dial() and listen() methods
2. Return net.Conn compatible interface
3. Support context cancellation
4. Handle TLS configuration (if applicable)
5. Respect source interface binding (linkInfo.sintf)
6. Work with links.findSuitableIP() for address resolution

### Notes

- All protocols return `net.Conn` for uniform handling
- Context support enables cancellation and timeouts
- WebSocket health checks useful for load balancers
- QUIC provides modern alternative to TCP
- WSS recommends reverse proxy for server-side TLS
- SOCKS useful in corporate/restricted environments
