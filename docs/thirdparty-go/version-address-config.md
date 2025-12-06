# Version, Address, and Config Management

## Overview
These files handle version information, IPv6 address derivation from keys, and platform-specific configuration defaults.

---

## version/version.go

### Purpose
Provides build name and version information, typically injected at compile time.

### Data Structures

#### Variables (set via linker flags)
- `buildName: string` - Name of the build (e.g., "yggdrasil")
- `buildVersion: string` - Version string (e.g., "0.5.0")

### APIs

#### `BuildName() string`
Returns build name, or "unknown" if not set.

#### `BuildVersion() string`
Returns build version, or "unknown" if not set.

### Linker Flag Injection
```bash
go build -ldflags="-X github.com/yggdrasil-network/yggdrasil-go/src/version.buildName=yggdrasil \
                    -X github.com/yggdrasil-network/yggdrasil-go/src/version.buildVersion=0.5.0"
```

### Comparison with yggdrasil-rs
**Status:** Should be implemented
- Rust: use `const` or environment variables at compile time
- Can use `build.rs` to inject git version
- Example: `env!("CARGO_PKG_VERSION")`
- Check if version info is exposed via API

---

## address/address.go

### Purpose
Derives IPv6 addresses and subnets from ed25519 public keys using Yggdrasil's addressing scheme.

### Data Structures

#### `Address [16]byte`
IPv6 address in Yggdrasil address range (128 bits).

#### `Subnet [8]byte`
IPv6 /64 subnet prefix (64 bits).

### Constants

#### `GetPrefix() [1]byte`
Returns address prefix: `0x02` (first byte of all Yggdrasil addresses).
- Addresses: `0x02` + `0` bit (node address)
- Subnets: `0x02` + `1` bit (subnet prefix)

### Addressing Scheme

The Yggdrasil addressing algorithm:

1. **Invert public key bits** - Compute bitwise NOT of key
2. **Count leading ones** - Count consecutive 1-bits from start
3. **Encode in address:**
   - Start with prefix `0x02`
   - Next bit: 0 for address, 1 for subnet
   - Next 7 bits: number of leading ones (0-127)
   - Remaining bits: inverted key bits after leading ones and first zero

This creates a cryptographically derived, collision-resistant address space.

### APIs

#### Address Validation

##### `(a *Address) IsValid() bool`
Checks if address starts with Yggdrasil prefix.

##### `(s *Subnet) IsValid() bool`
Checks if subnet starts with prefix and has subnet bit set.

#### Key-to-Address Derivation

##### `AddrForKey(publicKey ed25519.PublicKey) *Address`
Derives IPv6 address from public key:
1. Returns nil if key length ≠ 32 bytes
2. Inverts all key bits
3. Counts leading 1-bits
4. Skips leading 1s and first 0
5. Packs remaining bits into address
6. Prefix: `0x02` + `0` bit + ones count + key bits

##### `SubnetForKey(publicKey ed25519.PublicKey) *Subnet`
Derives /64 subnet from public key:
1. Calls `AddrForKey()` to get address
2. Truncates to first 64 bits
3. Sets subnet bit: prefix byte |= `0x01`

#### Address-to-Key Reconstruction

##### `(a *Address) GetKey() ed25519.PublicKey`
Reconstructs partial public key from address:
1. Extracts ones count from address
2. Sets leading 1-bits in key
3. Copies remaining address bits to key
4. Inverts all bits to restore original key
5. Returns partial key (used for DHT lookup)

**Note:** Not all key bits are present in address, so this is a *partial* key.

##### `(s *Subnet) GetKey() ed25519.PublicKey`
Converts subnet to address, then extracts key.

### Example Address Derivation

For a public key with:
- 5 leading 1-bits after inversion
- Remaining bits: `1010...`

Address structure:
```
0x02 | 0 | 0000101 | 1010...
^    ^ ^   ^         ^
|    | |   |         Remaining inverted key bits
|    | |   Leading ones count (5 in binary)
|    | Address bit (0 = address, 1 = subnet)
|    Fixed prefix bit
Prefix byte
```

### Comparison with yggdrasil-rs
**Status:** Should be in `yggdrasil-address` crate
- Critical for routing and DHT
- Check if addressing scheme is implemented
- Bit manipulation similar in Rust
- Verify prefix and bit ordering match Go implementation

---

## config/defaults.go

### Purpose
Defines platform-specific default configuration parameters.

### Data Structures

#### Build-time Variables (linker injection)
- `defaultConfig: string` - Path to default config file
- `defaultAdminListen: string` - Default admin socket address

#### `platformDefaultParameters`
- `DefaultAdminListen: string` - Admin socket URL
- `DefaultConfigFile: string` - Configuration file path
- `DefaultMulticastInterfaces: []MulticastInterfaceConfig` - Multicast settings
- `MaximumIfMTU: uint64` - Maximum TUN interface MTU
- `DefaultIfMTU: uint64` - Default TUN interface MTU
- `DefaultIfName: string` - Default TUN interface name

### APIs

#### `GetDefaults() platformDefaultParameters`
Returns platform-specific defaults:
1. Calls `getDefaults()` (platform-specific implementation)
2. Overrides with linker-injected values if set
3. Returns final defaults

### Platform-Specific Implementations

#### Linux (defaults_linux.go)
```go
DefaultAdminListen: "unix:///var/run/yggdrasil.sock"
DefaultConfigFile: "/etc/yggdrasil.conf"
DefaultMulticastInterfaces: [{Regex: ".*", Beacon: true, Listen: true}]
MaximumIfMTU: 65535
DefaultIfMTU: 65535
DefaultIfName: "auto"
```

#### Darwin/macOS (defaults_darwin.go)
- Admin: `unix:///var/run/yggdrasil.sock`
- Config: `/etc/yggdrasil.conf`
- MTU: 65535
- Name: `auto`

#### Windows (defaults_windows.go)
- Admin: `tcp://localhost:9001` (TCP instead of Unix socket)
- Config: `C:\ProgramData\Yggdrasil\yggdrasil.conf`
- MTU: 65535
- Name: `auto`

#### FreeBSD/OpenBSD
- Similar to Linux
- MTU may vary

#### Other (defaults_other.go)
- Generic Unix-like defaults
- Fallback for unsupported platforms

### Comparison with yggdrasil-rs
**Status:** Should be in `yggdrasil-config` crate
- Platform-specific defaults needed
- Rust: use conditional compilation (`#[cfg(target_os = "...")]`)
- Check if config crate has platform defaults
- Admin socket URL formats must match

---

## Summary

### Implemented in Go

1. **version/version.go**
   - Build name and version
   - Linker flag injection
   - Simple getter functions

2. **address/address.go**
   - IPv6 address derivation from ed25519 keys
   - Cryptographic addressing scheme
   - Partial key reconstruction
   - Address/subnet validation

3. **config/defaults.go**
   - Platform-specific defaults
   - Build-time override via linker flags
   - Admin socket, config file, MTU, multicast settings

### Rust Implementation Status

- **version** - Likely exists, check build info
- **address** - CRITICAL, should be in `yggdrasil-address` crate
- **config defaults** - Should be in `yggdrasil-config` with platform guards

### Priority for Implementation

1. **CRITICAL**: address.go - Core routing functionality
2. **HIGH**: config defaults - Required for proper operation
3. **MEDIUM**: version info - Useful for debugging

### Notes

#### Address Scheme
- Prefix `0x02` identifies Yggdrasil addresses
- Leading ones count enables efficient DHT routing
- Partial key reconstruction allows DHT lookups
- Cryptographically derived addresses prevent address spoofing

#### Config Defaults
- Windows uses TCP for admin (no Unix sockets)
- MTU typically 65535 (maximum Ethernet)
- Multicast on all interfaces by default (Linux)
- Config paths follow OS conventions

#### Version Info
- Injected at build time for official releases
- Returns "unknown" in development builds
- Used in node info and admin responses

### Critical Implementation Details

1. **Bit ordering** - Must match Go implementation exactly
2. **Key inversion** - Bitwise NOT of entire key
3. **Ones counting** - Leading 1-bits after inversion
4. **Prefix bit** - Address vs subnet distinction
5. **Partial keys** - Address doesn't contain all key bits
