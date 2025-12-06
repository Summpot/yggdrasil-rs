# Admin: error.go, getself.go, getsessions.go

## Overview
These files define admin API handlers for retrieving node information and active sessions.

---

## error.go

### Purpose
Defines standard error response format for admin API.

### Data Structures

#### `ErrorResponse`
- `Error: string` (JSON: `error`) - Error message

### Usage
Returned when admin API requests fail:
```json
{
  "error": "some error message"
}
```

### Comparison with yggdrasil-rs
**Status:** Should be implemented if admin API exists
- Simple error response structure
- Check admin/management module for error handling
- Rust would use `serde` for JSON serialization

---

## getself.go

### Purpose
Admin API handler to get information about the local node.

### Data Structures

#### `GetSelfRequest`
Empty struct (no parameters needed).

#### `GetSelfResponse`
- `BuildName: string` (JSON: `build_name`) - Software name
- `BuildVersion: string` (JSON: `build_version`) - Version string
- `PublicKey: string` (JSON: `key`) - Node's public key (hex-encoded)
- `IPAddress: string` (JSON: `address`) - Node's IPv6 address
- `RoutingEntries: uint64` (JSON: `routing_entries`) - Number of routing table entries
- `Subnet: string` (JSON: `subnet`) - Node's /64 subnet

### APIs

#### `(a *AdminSocket) getSelfHandler(_ *GetSelfRequest, res *GetSelfResponse) error`
Retrieves local node information:
1. Gets self info from core: `a.core.GetSelf()`
2. Gets subnet: `a.core.Subnet()`
3. Gets IPv6 address: `a.core.Address()`
4. Populates response with:
   - Build name/version from `version` package
   - Public key (hex-encoded)
   - IPv6 address
   - Subnet
   - Routing entries count
5. Returns nil (no errors possible)

### Example Response
```json
{
  "build_name": "yggdrasil",
  "build_version": "0.5.0",
  "key": "a1b2c3d4...",
  "address": "200:1234:5678:...",
  "subnet": "300:1234:5678::/64",
  "routing_entries": 42
}
```

### Comparison with yggdrasil-rs
**Status:** Should be in admin/management module
- Core functionality: GetSelf() likely implemented
- Check if admin API exists with similar endpoint
- Verify version info availability
- Rust: use `hex` crate for encoding, `serde` for JSON

---

## getsessions.go

### Purpose
Admin API handler to list all active sessions with remote nodes.

### Data Structures

#### `GetSessionsRequest`
Empty struct (no parameters needed).

#### `GetSessionsResponse`
- `Sessions: []SessionEntry` (JSON: `sessions`) - Array of active sessions

#### `SessionEntry`
- `IPAddress: string` (JSON: `address`) - Remote node's IPv6 address
- `PublicKey: string` (JSON: `key`) - Remote node's public key (hex-encoded)
- `RXBytes: DataUnit` (JSON: `bytes_recvd`) - Bytes received
- `TXBytes: DataUnit` (JSON: `bytes_sent`) - Bytes sent
- `Uptime: float64` (JSON: `uptime`) - Session duration in seconds

#### `DataUnit`
Custom type (defined elsewhere) for formatting byte counts (likely with human-readable units).

### APIs

#### `(a *AdminSocket) getSessionsHandler(_ *GetSessionsRequest, res *GetSessionsResponse) error`
Retrieves all active sessions:
1. Gets sessions from core: `a.core.GetSessions()`
2. For each session:
   - Derives IPv6 address from public key using `address.AddrForKey()`
   - Converts key to hex string
   - Extracts RX/TX byte counts and uptime
3. Sorts sessions by public key (stable sort)
4. Returns session list

### Example Response
```json
{
  "sessions": [
    {
      "address": "200:1234:5678:...",
      "key": "a1b2c3d4...",
      "bytes_recvd": 1048576,
      "bytes_sent": 2097152,
      "uptime": 3600.5
    }
  ]
}
```

### Comparison with yggdrasil-rs
**Status:** Check session tracking implementation
- Core needs to track active sessions with statistics
- Session tracking: likely in `yggdrasil-session` crate
- Check if GetSessions() is implemented
- Address derivation: should be in `yggdrasil-address`
- DataUnit formatting: custom display trait in Rust
- Sorting by key: straightforward in Rust

---

## Summary

### Implemented in Go

1. **error.go**
   - Standard error response format
   - Single field: error message

2. **getself.go**
   - Local node information API
   - Returns: build info, keys, addresses, routing entries
   - No parameters required

3. **getsessions.go**
   - Active sessions list API
   - Returns: remote addresses, keys, traffic stats, uptime
   - Sorted by public key

### Rust Implementation Status

- **error.go** - Simple, should exist if admin API present
- **getself.go** - Core GetSelf() likely exists, admin endpoint needed
- **getsessions.go** - Requires session tracking and statistics

### Priority for Implementation

1. **HIGH**: getself.go - Essential for node management
2. **HIGH**: getsessions.go - Critical for monitoring connections
3. **MEDIUM**: error.go - Standard error handling

### Notes

- These are read-only admin APIs (safe, no state changes)
- Session statistics tracking must be in core/session modules
- Address derivation from keys is cryptographic operation
- Sorting ensures consistent output for clients
- DataUnit type provides human-readable byte counts
- No pagination (assumes reasonable number of sessions)

### Integration Requirements

For yggdrasil-rs:
1. Admin socket/HTTP server for API
2. Core must expose GetSelf() and GetSessions()
3. Session module must track RX/TX bytes and uptime
4. Version information must be accessible
5. JSON serialization with serde
