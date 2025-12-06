# Core: types.go, version.go, proto.go

## Overview
These files define core protocol types, version negotiation, and protocol packet handling for Yggdrasil.

---

## types.go

### Purpose
Defines packet type constants for session and protocol packets.

### APIs / Constants
- **In-band packet types:**
  - `typeSessionDummy = 0` - Dummy/unused session packet
  - `typeSessionTraffic = 1` - Regular traffic packet
  - `typeSessionProto = 2` - Protocol control packet

- **Protocol packet types:**
  - `typeProtoDummy = 0` - Dummy/unused protocol packet
  - `typeProtoNodeInfoRequest = 1` - Request node information
  - `typeProtoNodeInfoResponse = 2` - Response with node information
  - `typeProtoDebug = 255` - Debug protocol messages

### Comparison with yggdrasil-rs
**Status:** Partially implemented
- Basic packet type constants would be in `yggdrasil-wire` or `yggdrasil-types` crates
- Check for enum-based packet type definitions in Rust
- Need to verify if debug protocol is implemented

---

## version.go

### Purpose
Handles protocol version negotiation and handshake at connection establishment.

### Data Structures

#### `version_metadata`
- `majorVer: uint16` - Protocol major version (currently 0)
- `minorVer: uint16` - Protocol minor version (currently 5)
- `publicKey: ed25519.PublicKey` - Node's public key (32 bytes)
- `priority: uint8` - Connection priority

#### Constants
- `ProtocolVersionMajor = 0`
- `ProtocolVersionMinor = 5`

#### Metadata fields (TLV format):
- `metaVersionMajor = 0` - Major version field ID
- `metaVersionMinor = 1` - Minor version field ID
- `metaPublicKey = 2` - Public key field ID
- `metaPriority = 3` - Priority field ID

### Error Types
- `ErrHandshakeInvalidPreamble` - Invalid "meta" preamble
- `ErrHandshakeInvalidLength` - Length mismatch, version incompatible
- `ErrHandshakeInvalidPassword` - Password validation failed
- `ErrHandshakeHashFailure` - Hash computation failed
- `ErrHandshakeIncorrectPassword` - Password doesn't match

### APIs

#### `version_getBaseMetadata() version_metadata`
Returns base metadata with current protocol version numbers.

#### `(m *version_metadata) encode(privateKey ed25519.PrivateKey, password []byte) ([]byte, error)`
Encodes version metadata into wire format:
1. Adds "meta" preamble (4 bytes)
2. Reserves 2 bytes for message length
3. Encodes TLV fields (major, minor, public key, priority)
4. Computes BLAKE2b-512 hash of public key with password
5. Signs hash with private key (ed25519 signature, 64 bytes)
6. Returns complete handshake message

#### `(m *version_metadata) decode(r io.Reader, password []byte) error`
Decodes and verifies version metadata:
1. Reads "meta" preamble and message length
2. Parses TLV-encoded fields
3. Verifies ed25519 signature using BLAKE2b-512 hash with password
4. Returns error if verification fails

#### `(m *version_metadata) check() bool`
Validates that major/minor versions match and public key is valid size.

### Comparison with yggdrasil-rs
**Status:** Likely implemented in `yggdrasil-crypto` or `yggdrasil-link`
- Handshake logic is critical for peer connections
- Check for version negotiation in link establishment code
- Verify BLAKE2b password-based authentication
- Confirm ed25519 signature verification

---

## proto.go

### Purpose
Handles protocol control messages including debug queries (GetSelf, GetPeers, GetTree) and node info exchange.

### Data Structures

#### Debug packet types:
- `typeDebugDummy = 0`
- `typeDebugGetSelfRequest = 1` - Request self info from remote node
- `typeDebugGetSelfResponse = 2` - Response with self info
- `typeDebugGetPeersRequest = 3` - Request peers list
- `typeDebugGetPeersResponse = 4` - Response with peers
- `typeDebugGetTreeRequest = 5` - Request routing tree
- `typeDebugGetTreeResponse = 6` - Response with tree

#### `reqInfo`
Tracks pending requests with callback and timeout timer.
- `callback: func([]byte)` - Called when response arrives
- `timer: *time.Timer` - 1-minute timeout for request

#### `keyArray [ed25519.PublicKeySize]byte`
Fixed-size array for public key (32 bytes).

#### `protoHandler`
Main protocol handler with actor-based concurrency (phony.Inbox).
- `core: *Core` - Reference to core
- `nodeinfo: nodeinfo` - Node info handler
- `selfRequests: map[keyArray]*reqInfo` - Pending GetSelf requests
- `peersRequests: map[keyArray]*reqInfo` - Pending GetPeers requests
- `treeRequests: map[keyArray]*reqInfo` - Pending GetTree requests

### APIs

#### `(p *protoHandler) init(core *Core)`
Initializes handler, nodeinfo, and request maps.

#### `(p *protoHandler) handleProto(from phony.Actor, key keyArray, bs []byte)`
Routes protocol packets based on first byte:
- NodeInfo request/response
- Debug messages

#### `(p *protoHandler) handleDebug(from phony.Actor, key keyArray, bs []byte)`
Routes debug protocol packets to appropriate handlers.

#### GetSelf Protocol
- `sendGetSelfRequest(key keyArray, callback func([]byte))` - Sends request with 1-minute timeout
- `_handleGetSelfRequest(key keyArray)` - Responds with self info (key, routing entries)
- `_handleGetSelfResponse(key keyArray, bs []byte)` - Processes response, invokes callback

#### GetPeers Protocol
- `sendGetPeersRequest(key keyArray, callback func([]byte))` - Sends request
- `_handleGetPeersRequest(key keyArray)` - Responds with peer public keys (respects MTU)
- `_handleGetPeersResponse(key keyArray, bs []byte)` - Processes response

#### GetTree Protocol
- `sendGetTreeRequest(key keyArray, callback func([]byte))` - Sends request
- `_handleGetTreeRequest(key keyArray)` - Responds with routing tree keys (respects MTU)
- `_handleGetTreeResponse(key keyArray, bs []byte)` - Processes response

### Admin Socket Handlers

#### `DebugGetSelfRequest / DebugGetSelfResponse`
Admin API to query remote node's self info.
- Takes hex-encoded public key
- Returns JSON with routing entries
- 6-second timeout

#### `DebugGetPeersRequest / DebugGetPeersResponse`
Admin API to query remote node's peers.
- Returns array of peer public keys
- Maps to IP address

#### `DebugGetTreeRequest / DebugGetTreeResponse`
Admin API to query remote node's routing tree.
- Returns array of tree node keys
- Maps to IP address

### Comparison with yggdrasil-rs
**Status:** Likely NOT fully implemented
- Debug protocol is advanced feature, may not be priority
- Admin API handlers would be in admin/management module
- Check if `yggdrasil-routing` or admin modules have debug queries
- Actor-based concurrency (phony) needs Rust equivalent (likely tokio actors or channels)
- Timeout handling and request tracking need verification

---

## Summary

### Implemented in Go
1. **Packet type constants** - Session and protocol packet identifiers
2. **Version negotiation** - Handshake with password-protected ed25519 signatures
3. **Debug protocol** - Remote queries for self, peers, and routing tree
4. **Node info protocol** - Exchange node information between peers

### Rust Implementation Status
- **types.go** - Likely in `yggdrasil-types` or `yggdrasil-wire`
- **version.go** - Should be in `yggdrasil-crypto` or `yggdrasil-link` for handshakes
- **proto.go** - Debug features may not be implemented yet

### Priority for Implementation
1. **HIGH**: Version negotiation and handshake (critical for compatibility)
2. **MEDIUM**: Basic protocol packet types
3. **LOW**: Debug protocol (nice-to-have for diagnostics)

### Notes
- Go uses actor model (phony) for concurrency - Rust would use tokio or async channels
- Password-based authentication in handshake is security-critical
- TLV encoding in version metadata allows protocol extensibility
