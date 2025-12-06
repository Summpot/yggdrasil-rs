# Peer Tracking Analysis

## Issue Description
When yggdrasil-rs and yggdrasil-go nodes connect:
- yggdrasil-go can see yggdrasil-rs as a peer (visible in get-peers)
- yggdrasil-rs cannot see yggdrasil-go as a peer (get-peers returns empty)

## How Peer Tracking Works in yggdrasil-rs

### Connection Establishment

#### Outbound Connections
1. `Links::connect()` or `Links::connect_uri()` is called
2. TCP/TLS connection is established
3. Handshake is performed (`perform_handshake()`)
4. `LinkState` is added to `self.links` HashMap with `conn: Some(...)`
5. `PeerConnectedEvent` is sent via `event_tx`
6. Main loop receives event and adds to `peer_registry`

#### Inbound Connections  
1. Accept loop receives incoming connection
2. `handle_incoming()` spawns handler for the connection
3. TLS handshake and Yggdrasil handshake are performed
4. `LinkState` is added to `self.links` HashMap with `conn: Some(...)`
5. `PeerConnectedEvent` is sent via `event_tx`
6. Main loop receives event and adds to `peer_registry`

### Peer Listing

When `getpeers` admin command is executed:
1. Admin server calls `links.get_links()`
2. `get_links()` returns all entries in `self.links` where `conn.is_some()`
3. Each link includes its metrics (`alive`, `rx_bytes`, `tx_bytes`)
4. All links are returned regardless of `alive` status

## Potential Issues

### Theory 1: Handshake Failure
If the handshake fails silently, the connection might not be added to the links HashMap.

**Evidence needed:**
- Check logs for handshake errors
- Verify that `LinkState` is actually being inserted

**Debug steps:**
```rust
// Add logging in Links::handle_incoming() after LinkState insertion
tracing::info!(
    uri = %uri,
    remote_key = %hex::encode(remote_key.as_bytes()),
    "LinkState inserted for incoming connection"
);
```

### Theory 2: Connection Cleanup
If connections are being cleaned up too aggressively, they might disappear from the list.

**Evidence needed:**
- Check if there's any code removing entries from `self.links`
- Current code review shows NO removal code exists

### Theory 3: Timing Issue
The `get-peers` command might be called before connections are fully established.

**Evidence needed:**
- Wait a few seconds after connection before checking peers
- Check if connections appear later

### Theory 4: URI Uniqueness
If multiple connection attempts use the same URI, the HashMap insert might replace previous entries.

**Evidence needed:**
- Check if URIs are unique for each connection
- For incoming connections, URI is `format!("tls://{}", remote_addr)`
- For outbound connections, URI is provided by user/config

### Theory 5: Links Not Started
If `Links::start()` is not called, the TLS acceptor won't be initialized.

**Evidence needed:**
- Verify `links.start()` is called before `links.listen()`
- Check logs for "Links manager started" message

## Recommended Debug Steps

1. **Enable debug logging:**
   ```bash
   RUST_LOG=yggdrasil=debug ./target/debug/yggdrasil run -c config.hjson
   ```

2. **Check connection logs:**
   - Look for "Peer connected" messages
   - Look for "LinkState inserted" (if we add this log)
   - Look for any handshake errors

3. **Verify Links state:**
   - Add a debug command to dump the raw `self.links` HashMap
   - Count entries and compare with expected peer count

4. **Test isolation:**
   - Test with a single static peer (non-multicast)
   - Test with outbound connection only
   - Test with inbound connection only

5. **Compare with yggdrasil-go:**
   - Check what yggdrasil-go does differently
   - Verify protocol compatibility

## Code Locations

- Links HashMap: `crates/yggdrasil-link/src/links.rs:139`
- Outbound connection: `crates/yggdrasil-link/src/links.rs:636-654`
- Inbound connection: `crates/yggdrasil-link/src/links.rs:451-469`
- get_links(): `crates/yggdrasil-link/src/links.rs:750-763`
- Admin getpeers: `src/admin_server.rs:844-887`

## Next Steps

1. Add more detailed logging to track Link state changes
2. Create a test scenario that reproduces the issue
3. Use tcpdump/wireshark to verify TCP connections are established
4. Check if the issue is specific to multicast-discovered peers or all peers
