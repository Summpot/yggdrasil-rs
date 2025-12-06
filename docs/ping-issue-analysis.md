# Ping Issue Analysis

## Summary

The ping failure observed on Windows is due to incomplete routing table configuration. While tun-rs automatically adds routes for the local node's addresses, it does not add routes for the entire yggdrasil address space needed to reach other nodes.

## Observations from Logs

1. **Node is running correctly**:
   - Local address: `200:231a:6fae:4668:1cde:32f:15a8:c3dd`
   - TUN adapter started successfully with MTU 65535
   - Peer connected successfully: `200:26e7:ac4c:fdd2:caaf:ad80:bb1d:d54f`

2. **TUN adapter is functional**:
   - Receiving and processing multicast/broadcast packets
   - ICMPv6 (next_header=58) packets are being received
   - Neighbor Discovery packets working

3. **Routing table shows partial routes**:
   - tun-rs automatically added: `200:231a:6fae:4668:1cde:32f:15a8:c3dd/128` (local address)
   - tun-rs automatically added: `300:231a:6fae:4668::/64` (local subnet)
   - **Missing**: Route for entire yggdrasil address space (200::/7 or 200::/8)

4. **No ping packets reach yggdrasil**:
   - All ICMPv6 packets in the log are to multicast (ff02::*) or link-local (fe80::*) addresses
   - No ICMP Echo Request packets to peer address `200:26e7:ac4c:fdd2:caaf:ad80:bb1d:d54f`
   - Peer address `200:26e7:ac4c:fdd2:*` has no matching route in the routing table

## Root Cause

**tun-rs only adds routes for the local node** (its own /128 address and /64 subnet). It does NOT add routes for the entire yggdrasil address space (200::/7), which is required to reach other nodes in the network.

When Windows tries to send a ping to `200:26e7:ac4c:fdd2:caaf:ad80:bb1d:d54f`:
1. It looks for a matching route in the routing table
2. Finds only `200:231a:*/128` (local address) - doesn't match
3. Finds `300:231a:*/64` (local subnet) - doesn't match
4. No default route for 200::/7 exists
5. Results in "PING：传输失败。常见故障。" (Transmission failed. General failure.)

## Solution

On Windows, you need to add a route to the yggdrasil address space through the TUN adapter:

```cmd
# Add route for yggdrasil address space (200::/7)
netsh interface ipv6 add route 200::/7 "Yggdrasil" metric=1

# Verify the route
route print -6
```

Alternatively, you can add specific routes:
```cmd
# For the standard yggdrasil address range
netsh interface ipv6 add route 200::/8 "Yggdrasil"
netsh interface ipv6 add route 300::/8 "Yggdrasil"
```

## Verification

After adding the route, try:
```cmd
ping 200:26e7:ac4c:fdd2:caaf:ad80:bb1d:d54f
```

The packets should now reach the yggdrasil TUN adapter and be logged/processed.

## Technical Details

**Why doesn't tun-rs add routes for the entire address space?**

The tun-rs library is a generic TUN/TAP adapter library that doesn't know about yggdrasil's specific addressing scheme. It only adds routes for the addresses explicitly assigned to the interface (the /128 host address and /64 subnet prefix).

Yggdrasil uses addresses from the 200::/7 block (200::/8 and 300::/8), but to reach OTHER nodes in the network, the OS needs to know to route ALL 200::/7 traffic through the yggdrasil TUN adapter, not just the local addresses.

## Note for Future Implementation

The yggdrasil application needs to explicitly add a route for 200::/7 (or 200::/8 + 300::/8) after creating the TUN adapter. This should be implemented in the main application code or the `yggdrasil-tun` crate's Windows-specific initialization.

Reference: yggdrasil-go does this automatically during TUN adapter setup. This is application-level routing configuration, not provided by tun-rs itself.
