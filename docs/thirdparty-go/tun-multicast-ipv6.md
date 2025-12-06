# TUN/TAP, Multicast, and IPv6 Modules

## Overview
These modules handle TUN/TAP interface management, multicast peer discovery, and IPv6 packet processing.

---

## TUN Module (src/tun/)

### Purpose
Manages TUN/TAP virtual network interface for routing IPv6 packets between Yggdrasil and applications.

### Files
- `tun.go` - Main TUN adapter implementation
- `admin.go` - Admin API handlers
- `options.go` - Configuration options
- `iface.go` - Platform-agnostic interface setup
- `tun_linux.go`, `tun_darwin.go`, etc. - Platform-specific implementations

### Data Structures

#### `TunAdapter`
Main TUN interface handler (actor-based with phony.Inbox).
- `rwc: ReadWriteCloser` - IPv6 read/write interface
- `log: core.Logger` - Logger
- `addr: address.Address` - Node's IPv6 address
- `subnet: address.Subnet` - Node's /64 subnet
- `mtu: uint64` - Interface MTU
- `iface: wgtun.Device` - WireGuard TUN device (cross-platform)
- `isOpen: bool` - Interface status
- `isEnabled: bool` - Enabled flag (for dropping traffic)
- `config` - Name, MTU, file descriptor
- `ch: chan []byte` - Packet buffer channel

#### `ReadWriteCloser` (interface)
- `io.ReadWriteCloser` - Standard read/write/close
- `Address() address.Address` - Node address
- `Subnet() address.Subnet` - Node subnet
- `MaxMTU() uint64` - Maximum MTU
- `SetMTU(uint64)` - Set MTU

### APIs

#### Initialization

##### `New(rwc ReadWriteCloser, log core.Logger, opts ...SetupOption) (*TunAdapter, error)`
Creates and starts TUN adapter:
1. Applies setup options (name, MTU, FD)
2. Calls `_start()` to configure interface

##### `(tun *TunAdapter) _start() error`
Starts TUN interface:
1. Gets address/subnet from rwc
2. Checks if disabled (name="none" or "dummy")
3. Sets up interface (via FD or by name)
4. Validates MTU (1280-65535)
5. Starts packet processing goroutines:
   - `queue()` - Buffers packets
   - `read()` - Reads from TUN
   - `write()` - Writes to TUN

#### Configuration

##### `DefaultName() string`
Platform-specific default interface name (e.g., "auto" on Linux).

##### `DefaultMTU() uint64`
Default MTU from platform defaults.

##### `MaximumMTU() uint64`
Maximum supported MTU (typically 65535).

##### `(tun *TunAdapter) MTU() uint64`
Returns current MTU (clamped to 1280-65535).

##### `(tun *TunAdapter) Name() string`
Returns interface name.

#### Lifecycle

##### `(tun *TunAdapter) IsStarted() bool`
Returns true if TUN is running.

##### `(tun *TunAdapter) Stop() error`
Stops TUN adapter and closes interface.

### Setup Options

#### `SetupOption` (interface)
- `InterfaceName` - TUN interface name
- `InterfaceMTU` - Interface MTU
- `FileDescriptor` - Pre-opened file descriptor

### Admin API

#### `GetTUNRequest / GetTUNResponse`
Retrieves TUN interface info:
- `Enabled: bool` - Is TUN enabled
- `Name: string` - Interface name
- `MTU: uint64` - Current MTU

### Buffer Pooling
- `bufPool` - sync.Pool for packet buffers (65535 bytes)
- `TUN_OFFSET_BYTES` - Offset for packet alignment

### Comparison with yggdrasil-rs
**Status:** Check `yggdrasil-tun` crate
- TUN creation: cross-platform challenging
- Rust: use `tun-tap` or `tun` crate
- WireGuard's `boringtun` has good TUN abstraction
- Priority: HIGH (critical for actual networking)

---

## Multicast Module (src/multicast/)

### Purpose
Discovers peers on local network via IPv6 multicast beacons.

### Files
- `multicast.go` - Main multicast handler
- `admin.go` - Admin API
- `advertisement.go` - Beacon packet format
- `options.go` - Configuration options
- `multicast_*.go` - Platform-specific socket options

### Data Structures

#### `Multicast`
Actor-based multicast handler.
- `core: *core.Core` - Core reference
- `log: *log.Logger` - Logger
- `sock: *ipv6.PacketConn` - IPv6 multicast socket
- `running: atomic.Bool` - Running state
- `_listeners: map[string]*listenerInfo` - Active listeners per interface
- `_interfaces: map[string]*interfaceInfo` - Configured interfaces
- `_timer: *time.Timer` - Announcement timer
- `config` - Group address, interfaces

#### `interfaceInfo`
Per-interface multicast configuration.
- `iface: net.Interface` - Network interface
- `addrs: []net.Addr` - Link-local addresses
- `beacon: bool` - Send beacons
- `listen: bool` - Listen for beacons
- `port: uint16` - Listen port
- `priority: uint8` - Connection priority
- `password: []byte` - Optional password
- `hash: []byte` - BLAKE2b hash of password+key

#### `listenerInfo`
Tracks listener for auto-peering.
- `listener: *core.Listener` - Core listener
- `time: time.Time` - Last announcement
- `interval: time.Duration` - Announcement interval
- `port: uint16` - Listen port

#### `multicastAdvertisement`
Beacon packet structure.
- `MajorVersion: uint16` - Protocol major version
- `MinorVersion: uint16` - Protocol minor version
- `PublicKey: ed25519.PublicKey` - Node's public key
- `Port: uint16` - Listen port
- `Hash: []byte` - Password hash (BLAKE2b-512)

### APIs

#### Initialization

##### `New(core *core.Core, log *log.Logger, opts ...SetupOption) (*Multicast, error)`
Creates and starts multicast module:
1. Applies options (interfaces, group address)
2. Resolves multicast group (default: `[ff02::114]:9001`)
3. Creates IPv6 socket with multicast reuse
4. Starts listener goroutine
5. Begins announcement cycle

##### `(m *Multicast) _start() error`
Starts multicast:
1. Checks if any interface has beacon or listen enabled
2. Creates UDP6 socket on all interfaces
3. Enables IPv6 control messages
4. Starts `listen()` goroutine
5. Triggers interface updates and announcements

#### Interface Management

##### `(m *Multicast) _updateInterfaces()`
Updates list of active multicast interfaces:
1. Enumerates all network interfaces
2. Filters: UP, RUNNING, MULTICAST, not P2P
3. Matches against configured regexes
4. Extracts link-local IPv6 addresses
5. Computes password hash (BLAKE2b)

##### `(m *Multicast) _getAllowedInterfaces() map[string]*interfaceInfo`
Returns map of enabled interfaces with configuration.

##### `(m *Multicast) Interfaces() map[string]net.Interface`
Public API to get active interfaces.

#### Beacon Transmission

##### `(m *Multicast) _announce()`
Sends multicast beacons on all enabled interfaces:
1. Updates interface list
2. For each interface with beacon=true:
   - Creates listener if needed
   - Marshals advertisement packet
   - Sends to multicast group on that interface
3. Schedules next announcement (with jitter)

##### `(m *Multicast) AnnounceNow()`
Triggers immediate announcement (bypasses timer).

#### Beacon Reception

##### `(m *Multicast) listen()`
Receives multicast beacons:
1. Reads packets from multicast socket
2. Unmarshals advertisement
3. Verifies protocol version
4. Checks password hash
5. Extracts source address and port
6. Calls core to establish connection

#### Lifecycle

##### `(m *Multicast) IsStarted() bool`
Returns true if multicast is running.

##### `(m *Multicast) Stop() error`
Stops multicast module and closes socket.

### Advertisement Format

Binary format (big-endian):
```
[MajorVersion:2][MinorVersion:2][PublicKey:32][Port:2][HashLen:2][Hash:variable]
```

- Total: 40+ bytes
- Hash typically 64 bytes (BLAKE2b-512)
- Versioned for protocol compatibility

### Admin API

#### `GetMulticastInterfacesRequest / Response`
Lists active multicast interfaces:
- `Name: string` - Interface name
- `Address: string` - Listener address
- `Beacon: bool` - Sending beacons
- `Listen: bool` - Listening for beacons
- `Password: bool` - Password enabled

### Platform-Specific Socket Options

Different OSes require different socket options for multicast:
- **Unix (Linux, BSD)**: Standard multicast socket options
- **Darwin (macOS)**: Special handling, optionally uses Objective-C bridge
- **Windows**: Different multicast join semantics

### Comparison with yggdrasil-rs
**Status:** Check `yggdrasil-multicast` crate
- IPv6 multicast: use `socket2` crate
- Link-local discovery: important for LAN
- Password protection: BLAKE2b verification
- Priority: MEDIUM-HIGH (useful for auto-peering)

---

## IPv6 Module (src/ipv6rwc/)

### Purpose
Provides IPv6 packet read/write interface with address-to-key mapping and ICMPv6 support.

### Files
- `ipv6rwc.go` - Main IPv6 packet handler
- `icmpv6.go` - ICMPv6 packet generation

### Data Structures

#### `keyStore`
Maps IPv6 addresses/subnets to ed25519 public keys.
- `core: *core.Core` - Core reference
- `address: address.Address` - Local address
- `subnet: address.Subnet` - Local subnet
- `keyToInfo: map[keyArray]*keyInfo` - Key to address mapping
- `addrToInfo: map[address.Address]*keyInfo` - Address to key
- `addrBuffer: map[address.Address]*buffer` - Buffered packets (pending lookup)
- `subnetToInfo: map[address.Subnet]*keyInfo` - Subnet to key
- `subnetBuffer: map[address.Subnet]*buffer` - Buffered subnet packets
- `mtu: uint64` - Current MTU

#### `keyInfo`
Cached address-key mapping.
- `key: keyArray` - ed25519 public key
- `address: address.Address` - Derived IPv6 address
- `subnet: address.Subnet` - Derived subnet
- `timeout: *time.Timer` - 2-minute expiry timer

#### `buffer`
Pending packet waiting for key lookup.
- `packet: []byte` - Buffered packet
- `timeout: *time.Timer` - 2-minute expiry

#### `ReadWriteCloser`
Implements TUN ReadWriteCloser interface.
- Embeds `keyStore` for packet handling

### APIs

#### Initialization

##### `NewReadWriteCloser(c *core.Core) *ReadWriteCloser`
Creates IPv6 packet handler:
1. Initializes key store
2. Sets up address-key mappings
3. Registers path notification callback

##### `(k *keyStore) init(c *core.Core)`
Initializes keyStore:
1. Derives local address and subnet from public key
2. Sets path notification handler
3. Initializes mapping tables
4. Sets default MTU (1280)

#### Address-Key Mapping

##### `(k *keyStore) update(key ed25519.PublicKey) *keyInfo`
Updates key mapping:
1. Creates keyInfo if new
2. Derives address and subnet from key
3. Checks for buffered packets
4. Sends buffered packets to destination
5. Resets 2-minute timeout

##### `(k *keyStore) resetTimeout(info *keyInfo)`
Resets key timeout to 2 minutes.
After timeout, removes from all mapping tables.

#### Key Lookup

##### `(k *keyStore) sendKeyLookup(partial ed25519.PublicKey)`
Initiates DHT lookup for partial public key.
- Used when destination address has no known key
- Core handles DHT traversal

#### Packet Sending

##### `(k *keyStore) sendToAddress(addr address.Address, bs []byte)`
Sends packet to IPv6 address:
1. Looks up key for address
2. If found: sends immediately, resets timeout
3. If not found: buffers packet, initiates lookup

##### `(k *keyStore) sendToSubnet(subnet address.Subnet, bs []byte)`
Sends packet to /64 subnet:
- Similar to sendToAddress but for subnet routing

#### Packet Reading

##### `(k *keyStore) readPC(p []byte) (int, error)`
Reads IPv6 packet from core:
1. Receives packet from core
2. Validates IPv6 header (version 6)
3. Checks packet length ≤ MTU
4. If too big: sends ICMPv6 Packet Too Big
5. Extracts source/dest addresses
6. Validates addresses match expectations
7. Updates key mapping for sender
8. Copies to output buffer

#### Packet Writing

##### `(k *keyStore) writePC(bs []byte) (int, error)`
Writes IPv6 packet to core:
1. Validates IPv6 packet
2. Extracts source/dest addresses
3. Validates source is local address/subnet
4. Routes based on destination:
   - Address: sendToAddress()
   - Subnet: sendToSubnet()

#### MTU Management

##### `(k *keyStore) MaxMTU() uint64`
Returns maximum MTU from core.

##### `(k *keyStore) SetMTU(mtu uint64)`
Sets MTU (1280-core.MTU).

##### `(k *keyStore) MTU() uint64`
Returns current MTU.

### ICMPv6 Support (icmpv6.go)

#### `CreateICMPv6(dst, src net.IP, mtype ipv6.ICMPType, mcode int, mbody icmp.MessageBody) ([]byte, error)`
Creates ICMPv6 packet with IPv6 header:
1. Marshals ICMP message body
2. Computes ICMP checksum (with pseudo-header)
3. Creates IPv6 header (version 6, next header 58, hop limit 255)
4. Concatenates IPv6 header + ICMP message
5. Returns complete packet

#### Common ICMPv6 Messages
- **Packet Too Big**: MTU exceeded, informs sender
- **Destination Unreachable**: Host/network unreachable
- **NDP messages**: Neighbor Discovery (TAP mode)

### Comparison with yggdrasil-rs
**Status:** Should be in `yggdrasil-tun` or separate crate
- Address-key mapping: critical for routing
- Packet buffering: handles lookup latency
- ICMPv6: required for proper IPv6 behavior
- MTU handling: prevents fragmentation issues
- Priority: HIGH (essential for TUN operation)

---

## Summary

### Implemented in Go

1. **TUN Module**
   - Cross-platform TUN/TAP interface
   - WireGuard device abstraction
   - MTU negotiation (1280-65535)
   - Admin API for status
   - Packet buffering

2. **Multicast Module**
   - IPv6 multicast discovery
   - Beacon transmission/reception
   - Password-protected groups
   - Per-interface configuration
   - Regex-based interface matching
   - Auto-peering on beacon receipt

3. **IPv6 Module**
   - Address-to-key mapping
   - Packet buffering during lookup
   - ICMPv6 generation
   - MTU enforcement
   - Timeout-based cleanup

### Rust Implementation Status

- **TUN** - Check if implemented, cross-platform challenging
- **Multicast** - Likely partially implemented
- **IPv6** - Should be integrated with TUN

### Priority for Implementation

1. **CRITICAL**: TUN - Required for actual networking
2. **HIGH**: IPv6 packet handling - Essential with TUN
3. **MEDIUM**: Multicast - Useful for LAN discovery

### Integration Notes

- TUN requires elevated privileges on most OSes
- Multicast uses link-local addresses (fe80::/10)
- Default multicast group: ff02::114:9001
- Password hashing: BLAKE2b-512(password || public_key)
- Key lookup timeout: 2 minutes
- Multicast announcement: randomized interval (prevents storms)

### Platform Considerations

- **Linux**: TUN via `/dev/net/tun`, multicast straightforward
- **macOS**: Special TUN setup, multicast requires Obj-C for zones
- **Windows**: TUN via TAP adapter, different multicast semantics
- **BSD**: Similar to Linux but different TUN paths

### Key Features

1. **Auto-discovery**: Multicast finds LAN peers automatically
2. **Password protection**: Prevents unwanted multicast peering
3. **Lazy key lookup**: Buffers packets while resolving addresses
4. **MTU handling**: Sends ICMPv6 PTB when necessary
5. **Platform abstraction**: Single codebase, platform-specific bits isolated
