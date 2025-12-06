# Core: pool.go, nodeinfo.go, debug.go

## Overview
These files provide memory pooling, node information exchange, and debugging support.

---

## pool.go

### Purpose
Provides memory pooling for byte slices to reduce allocations and GC pressure.

### APIs

#### `bytePool sync.Pool`
Global byte slice pool using Go's `sync.Pool`.

#### `allocBytes(size int) []byte`
Allocates or reuses byte slice from pool:
- Gets slice from pool
- If capacity insufficient, allocates new slice
- Returns slice with exact requested size

#### `freeBytes(bs []byte)`
Returns byte slice to pool:
- Resets slice length to 0 (keeps capacity)
- Puts back in pool for reuse

### Comparison with yggdrasil-rs
**Status:** Different approach in Rust
- Rust has different memory management (ownership, no GC)
- May use buffer pools from crates like `bytes` or custom allocators
- Less critical in Rust due to RAII and zero-cost abstractions
- Check if any buffer pooling exists in `yggdrasil-wire` or I/O modules

---

## nodeinfo.go

### Purpose
Manages node information exchange between peers, including caching and request/response handling.

### Data Structures

#### `nodeinfo`
Actor-based handler (phony.Inbox) for node info protocol.
- `proto: *protoHandler` - Reference to protocol handler
- `myNodeInfo: json.RawMessage` - Current node's info (JSON)
- `callbacks: map[keyArray]nodeinfoCallback` - Pending callbacks

#### `nodeinfoCallback`
- `call: func(nodeinfo json.RawMessage)` - Callback function
- `created: time.Time` - Timestamp for cleanup

### APIs

#### `(m *nodeinfo) init(proto *protoHandler)`
Initializes nodeinfo handler and starts cleanup goroutine.

#### `(m *nodeinfo) _cleanup()`
Periodic cleanup (every 30 seconds):
- Removes callbacks older than 1 minute
- Reschedules itself

#### `(m *nodeinfo) _addCallback(sender keyArray, call func(nodeinfo json.RawMessage))`
Registers callback for expected response from sender.

#### `(m *nodeinfo) _callback(sender keyArray, nodeinfo json.RawMessage)`
Invokes callback when response arrives, then removes it.

#### `(m *nodeinfo) _getNodeInfo() json.RawMessage`
Returns current node's info.

#### `(m *nodeinfo) setNodeInfo(given map[string]interface{}, privacy bool) error`
Sets node's information:
- Accepts arbitrary key-value pairs
- If `privacy=false`, adds build info:
  - `buildname` - Build name
  - `buildversion` - Version string
  - `buildplatform` - OS (GOOS)
  - `buildarch` - Architecture (GOARCH)
- Maximum size: 16384 bytes (after JSON encoding)
- Returns error if marshaling fails or size exceeded

#### `(m *nodeinfo) sendReq(from phony.Actor, key keyArray, callback func(nodeinfo json.RawMessage))`
Sends node info request to peer:
- Registers callback if provided
- Sends `typeProtoNodeInfoRequest` packet

#### `(m *nodeinfo) handleReq(from phony.Actor, key keyArray)`
Handles incoming request:
- Sends response with current node info

#### `(m *nodeinfo) handleRes(from phony.Actor, key keyArray, info json.RawMessage)`
Handles incoming response:
- Invokes registered callback

#### `(m *nodeinfo) _sendRes(key keyArray)`
Sends node info response:
- Constructs packet: `[typeSessionProto, typeProtoNodeInfoResponse, ...nodeinfo]`
- Writes to peer via PacketConn

### Admin API

#### `GetNodeInfoRequest`
- `Key: string` - Hex-encoded public key of target node

#### `GetNodeInfoResponse`
- `map[string]json.RawMessage` - Keyed by public key

#### `(m *nodeinfo) nodeInfoAdminHandler(in json.RawMessage) (interface{}, error)`
Admin socket handler:
1. Decodes request with target key
2. Sends node info request
3. Waits up to 6 seconds for response
4. Returns node info or timeout error

### Comparison with yggdrasil-rs
**Status:** Likely NOT implemented
- Node info is optional feature for network discovery/diagnostics
- Check if any nodeinfo module exists
- Admin API integration would be needed
- JSON serialization is straightforward in Rust with `serde_json`
- Privacy flag useful for public nodes

---

## debug.go

### Purpose
Enables profiling and debugging via pprof when environment variable is set.

### APIs

#### `init()`
Package initialization:
- Checks `PPROFLISTEN` environment variable
- If set, starts HTTP pprof server on specified address
- Imports `net/http/pprof` for profiling endpoints

### Usage
```bash
PPROFLISTEN=localhost:6060 ./yggdrasil
```
Then access profiling at http://localhost:6060/debug/pprof/

### Endpoints (standard Go pprof)
- `/debug/pprof/` - Index page
- `/debug/pprof/cmdline` - Command line
- `/debug/pprof/profile` - CPU profile
- `/debug/pprof/symbol` - Symbol resolution
- `/debug/pprof/trace` - Execution trace
- `/debug/pprof/heap` - Heap profile
- `/debug/pprof/goroutine` - Goroutine stack traces
- `/debug/pprof/threadcreate` - Thread creation profile
- `/debug/pprof/block` - Block profile
- `/debug/pprof/mutex` - Mutex contention profile

### Comparison with yggdrasil-rs
**Status:** NOT applicable (Go-specific)
- Rust uses different profiling tools:
  - `cargo-flamegraph` for flamegraphs
  - `perf` on Linux
  - `valgrind` for memory analysis
  - `tokio-console` for async runtime inspection
- Could implement similar HTTP debug endpoint with Rust tools
- Lower priority feature

---

## Summary

### Implemented in Go

1. **pool.go**
   - Byte slice pooling for reduced allocations
   - Simple get/release API

2. **nodeinfo.go**
   - Node information exchange protocol
   - Request/response with callbacks
   - Configurable privacy (hide build info)
   - Size limit (16 KB)
   - Admin API for remote queries
   - Automatic callback cleanup

3. **debug.go**
   - Runtime profiling via pprof
   - HTTP server for diagnostics

### Rust Implementation Status

- **pool.go** - Different approach needed, possibly using `bytes` crate
- **nodeinfo.go** - NOT implemented, optional feature
- **debug.go** - NOT applicable, use Rust profiling tools

### Priority for Implementation

1. **LOW**: pool.go - Rust memory management differs
2. **MEDIUM**: nodeinfo.go - Useful for debugging but not critical
3. **LOW**: debug.go - Use Rust-native profiling

### Notes

- Node info is optional and primarily for diagnostics
- 16 KB size limit is reasonable for preventing abuse
- Privacy flag prevents information leakage on public nodes
- Callback cleanup prevents memory leaks from lost responses
- Actor model (phony) would map to Rust async actors or channels
