# Yggdrasil Interoperability Tests

This directory contains comprehensive interoperability tests for Yggdrasil nodes.

## Test Categories

### Basic Tests (Always Available)

These tests run without special privileges:

1. **test_two_rust_nodes_direct** - Two Rust nodes direct connection
2. **test_three_rust_nodes_chain** - Three nodes in chain topology
3. **test_four_rust_nodes_mesh** - Four nodes in mesh topology
4. **test_access_control_allowed_keys** - Public key whitelist enforcement
5. **test_multiple_listen_addresses** - Multiple listen ports
6. **test_config_format_compatibility** - HJSON/JSON format parsing

Run basic tests:
```bash
cargo test --test interop_test -- --nocapture
```

### TUN Device Tests (Requires Sudo)

Test 8 requires TUN device creation which needs root privileges:

- **test_two_nodes_with_tun** - Two nodes with TUN devices

**The test will automatically skip if sudo is not available.**

#### Setup for TUN Tests

1. **Configure passwordless sudo** (recommended for testing):

   Add to `/etc/sudoers` or create `/etc/sudoers.d/yggdrasil-test`:
   ```
   your_username ALL=(ALL) NOPASSWD: /usr/bin/cargo, /usr/bin/env, /usr/bin/bash, /usr/bin/env
   ```

   Or use `visudo`:
   ```bash
   sudo visudo -f /etc/sudoers.d/yggdrasil-test
   ```

2. **Configure cargo runner** in `.cargo/config.toml`:
   ```toml
   [target.x86_64-unknown-linux-gnu]
   runner = 'sudo -E'
   ```

3. **Alternative: Run tests with sudo**:
   ```bash
   sudo -E cargo test --test interop_test test_two_nodes_with_tun -- --nocapture
   ```

### Stress Tests (Resource Intensive)

These tests are marked as `#[ignore]` and only run when explicitly requested:

- **test_stress_ten_nodes** - 10 nodes in chain topology

Run stress tests:
```bash
cargo test --test interop_test test_stress_ten_nodes -- --nocapture --ignored
```

### Go Interoperability Tests (Requires yggdrasil-go)

These tests require the Go implementation binary:

- **test_rust_connects_to_go** - Rust node connects to Go node
- **test_go_connects_to_rust** - Go node connects to Rust node
- **test_go_as_relay_between_rust_nodes** - Go node relays between two Rust nodes (Rust1 <-> Go <-> Rust2)
- **test_mixed_go_rust_network** - Mixed network with multiple Go and Rust nodes (Rust1 <-> Go1 <-> Go2 <-> Rust2)
- **test_rust_go_access_control** - Access control (AllowedPublicKeys) between Rust and Go nodes
- **test_multiple_rust_to_one_go** - Multiple Rust nodes connecting to single Go hub
- **test_alternating_rust_go_chain** - Chain of alternating Rust and Go nodes (5 nodes total)
- **test_rust_go_bidirectional** - Bidirectional connections between Rust and Go implementations

#### Setup for Go Tests

1. Build yggdrasil-go:
   ```bash
   cd thirdparty/yggdrasil-go
   ./build
   ```

2. Run Go interop tests:
   ```bash
   # Run all Go interop tests
   cargo test --test interop_test --ignored -- --nocapture --test-threads=1
   
   # Run specific tests
   cargo test --test interop_test test_rust_connects_to_go -- --nocapture --ignored
   cargo test --test interop_test test_go_as_relay_between_rust_nodes -- --nocapture --ignored
   cargo test --test interop_test test_mixed_go_rust_network -- --nocapture --ignored
   ```

## Test Scenarios Overview

### Basic Rust-to-Rust Tests (7 tests)
1. Two nodes direct connection
2. Three nodes chain topology
3. Four nodes mesh topology
4. Access control (AllowedPublicKeys)
5. Multiple listen addresses
6. Configuration format compatibility
7. Two nodes with TUN devices (auto-skip without sudo)

### Stress Tests (1 test)
8. Ten nodes chain topology

### Go Interoperability Tests (8 tests)
9. Rust connects to Go
10. Go connects to Rust
11. Go as relay between Rust nodes
12. Mixed Go/Rust network (4 nodes)
13. Access control between Rust and Go
14. Multiple Rust nodes to one Go hub
15. Alternating Rust/Go chain (5 nodes)
16. Bidirectional Rust<->Go connections

**Total: 16 comprehensive interoperability tests**

### Detailed Test Topologies

#### Test 9: Rust → Go
```
Rust Node --connect--> Go Node
```

#### Test 10: Go → Rust
```
Go Node --connect--> Rust Node (listener)
```

#### Test 11: Go as Relay
```
Rust1 <---> Go <---> Rust2
```
Tests routing through Go implementation.

#### Test 12: Mixed Network
```
Rust1 <---> Go1 <---> Go2 <---> Rust2
```
Complex 4-node mixed implementation network.

#### Test 13: Access Control
```
Rust1 (allowed) ---> Go (restricted)
Rust2 (blocked)  -X-> Go (restricted)
```
Tests AllowedPublicKeys between implementations.

#### Test 14: Hub Topology
```
        Go (hub)
       / | \
      /  |  \
  Rust1 Rust2 Rust3
```
Multiple Rust nodes connecting to single Go hub.

#### Test 15: Alternating Chain
```
Rust1 <--> Go1 <--> Rust2 <--> Go2 <--> Rust3
```
5-node chain alternating between implementations.

#### Test 16: Bidirectional
```
Rust1 (listener) <---> Go2 (client)
    ^                      ^
    |                      |
    v                      v
Go1 (client)        Rust2 (client)
```
Tests both implementations as servers and clients.

## Running All Tests

### Quick test (basic tests only):
```bash
cargo test --test interop_test -- --nocapture --test-threads=1
```

### Full test suite (including ignored tests):
```bash
cargo test --test interop_test -- --nocapture --ignored --test-threads=1
```

### Run only Go interop tests:
```bash
# All Go tests
cargo test --test interop_test --ignored -- --nocapture --test-threads=1 \
  test_rust_connects_to_go \
  test_go_connects_to_rust \
  test_go_as_relay_between_rust_nodes \
  test_mixed_go_rust_network \
  test_rust_go_access_control \
  test_multiple_rust_to_one_go \
  test_alternating_rust_go_chain \
  test_rust_go_bidirectional

# Or run individually
cargo test --test interop_test test_rust_connects_to_go -- --nocapture --ignored
cargo test --test interop_test test_go_as_relay_between_rust_nodes -- --nocapture --ignored
cargo test --test interop_test test_mixed_go_rust_network -- --nocapture --ignored
```

### Use the convenience script:
```bash
./test_interop.sh
```

## Test Output

Each test prints detailed information including:
- Node addresses (IPv6)
- Public keys (hex)
- Connection status
- Test results

Example output:
```
=== Test 1: Two Rust nodes - Direct connection ===
✓ Node 1 started
  Listen: tcp://127.0.0.1:19001
  Address: 200:e8ab:9077:c67e:163f:b1c1:4002:ce1
  Public key: 8baa37c41cc0f4e0271f5ffef98f5a9ebbd66c83b79ab1caadb414a3e5c2648b
✓ Node 2 started
  Listen: tcp://127.0.0.1:19002
  Address: 200:2650:d85b:65c8:7ae2:a455:3e96:edcf
  Public key: ecd793d24d1bc28eadd560b489186bfa8050ed98a845070658d4d36ad2a386cf
  Connecting to node 1...
✓ Test passed: Two nodes running and connected
```

## Test Architecture

### YggdrasilRustNode
Helper struct that manages Rust node instances:
- Generates temporary configuration files
- Starts node processes
- Tracks node metadata (address, public key, ports)
- Automatic cleanup on drop

### YggdrasilGoNode
Helper struct for Go implementation interoperability testing:
- Similar to YggdrasilRustNode but for Go nodes
- Used in cross-implementation tests

## Troubleshooting

### "TUN device requires sudo privileges"
- Configure passwordless sudo (see TUN Device Tests section)
- Or run with: `sudo -E cargo test ...`

### "Yggdrasil Rust binary not found"
- Run: `cargo build --workspace`

### "Yggdrasil-go binary not found"
- Build Go implementation: `cd thirdparty/yggdrasil-go && ./build`

### Tests hang or timeout
- Ensure no other Yggdrasil instances are using the test ports (19000-19099, 29000-29099)
- Check firewall settings
- Increase timeout if running on slow hardware

### "Address already in use"
- Wait a few seconds between test runs
- Or use `--test-threads=1` to run tests sequentially

## Port Allocations

Tests use the following port ranges:
- **19001-19013**: Basic topology tests (Rust-only)
- **19021-19024**: Mesh topology test
- **19031-19033**: Access control test
- **19041-19042**: Multiple listen addresses test
- **19051-19060**: Stress test (10 nodes)
- **19061-19062**: TUN device test
- **29001-29099**: Admin API ports (Rust nodes)
- **9001-9064**: Go interoperability tests
  - 9001-9003: Basic Rust<->Go tests
  - 9011-9013: Go relay test
  - 9021-9024: Mixed network test
  - 9031-9033: Access control test
  - 9041-9044: Hub topology test
  - 9051-9055: Alternating chain test
  - 9061-9064: Bidirectional test

## Security Note

The passwordless sudo configuration should only be used in development/testing environments. For production deployments, use proper capability management or systemd socket activation.
