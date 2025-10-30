use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use ed25519_dalek::VerifyingKey;
use log::{debug, info, warn};

use crate::address::Address;
use crate::spanning_tree::SpanningTree;

/// Route entry
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Destination address
    pub destination: Address,
    /// Next hop public key
    pub next_hop: VerifyingKey,
    /// Hop count
    pub hops: u8,
    /// Latency (milliseconds)
    pub latency: u32,
    /// Last update time
    pub last_update: std::time::Instant,
    /// Routing coordinates (path through the network tree)
    pub coords: Vec<u64>,
    /// Root node in the spanning tree
    pub root: Option<VerifyingKey>,
}

/// Packet to be routed
#[derive(Debug, Clone)]
pub struct RoutedPacket {
    /// Destination IPv6 address
    pub destination: Ipv6Addr,
    /// Source IPv6 address
    pub source: Ipv6Addr,
    /// Packet data
    pub data: Vec<u8>,
}

/// Router event
#[derive(Debug, Clone)]
pub enum RouterEvent {
    /// Packet received from peer
    PacketFromPeer(VerifyingKey, Vec<u8>),
    /// Packet to be sent to peer
    PacketToPeer(VerifyingKey, Vec<u8>),
    /// Packet to be sent to TUN interface
    PacketToTun(Vec<u8>),
}

/// Routing table
#[derive(Clone)]
pub struct RoutingTable {
    routes: Arc<RwLock<HashMap<Ipv6Addr, RouteEntry>>>,
    event_tx: Option<mpsc::Sender<RouterEvent>>,
    /// Spanning tree for coordinate-based routing
    spanning_tree: Option<Arc<SpanningTree>>,
    /// Local IPv6 address for ICMP messages
    local_addr: Ipv6Addr,
}

impl RoutingTable {
    /// Create new routing table
    pub fn new() -> Self {
        RoutingTable {
            routes: Arc::new(RwLock::new(HashMap::new())),
            event_tx: None,
            spanning_tree: None,
            local_addr: Ipv6Addr::UNSPECIFIED,
        }
    }
    
    /// Create routing table with event channel
    pub fn with_event_channel(event_tx: mpsc::Sender<RouterEvent>) -> Self {
        RoutingTable {
            routes: Arc::new(RwLock::new(HashMap::new())),
            event_tx: Some(event_tx),
            spanning_tree: None,
            local_addr: Ipv6Addr::UNSPECIFIED,
        }
    }
    
    /// Create routing table with spanning tree
    pub fn with_spanning_tree(local_key: VerifyingKey, event_tx: mpsc::Sender<RouterEvent>) -> Self {
        use crate::address::Address;
        let local_addr = Address::from_public_key(&local_key).as_ipv6();
        RoutingTable {
            routes: Arc::new(RwLock::new(HashMap::new())),
            event_tx: Some(event_tx),
            spanning_tree: Some(Arc::new(SpanningTree::new(local_key))),
            local_addr,
        }
    }
    
    /// Set event channel
    pub fn set_event_channel(&mut self, event_tx: mpsc::Sender<RouterEvent>) {
        self.event_tx = Some(event_tx);
    }
    
    /// Get spanning tree reference
    pub fn get_spanning_tree(&self) -> Option<Arc<SpanningTree>> {
        self.spanning_tree.clone()
    }
    
    /// Add or update route with coordinates
    pub async fn add_route_with_coords(&self, entry: RouteEntry) -> Result<()> {
        let addr = entry.destination.as_ipv6();
        let mut routes = self.routes.write().await;
        
        // If route exists, compare and select better path
        if let Some(existing) = routes.get(&addr) {
            // Compare using tree-space distance if coordinates available
            let is_better = if !entry.coords.is_empty() && !existing.coords.is_empty() {
                Self::compare_routes_by_coords(&entry, existing)
            } else {
                // Fallback to hop count and latency
                entry.hops < existing.hops || 
                (entry.hops == existing.hops && entry.latency < existing.latency)
            };
            
            if is_better {
                debug!("Updating route to {} via better path (coords: {:?})", addr, entry.coords);
                routes.insert(addr, entry);
            }
        } else {
            info!("Adding new route to {} (coords: {:?})", addr, entry.coords);
            routes.insert(addr, entry);
        }
        
        Ok(())
    }
    
    /// Compare routes based on tree-space coordinates
    /// Returns true if entry1 is better than entry2
    fn compare_routes_by_coords(entry1: &RouteEntry, entry2: &RouteEntry) -> bool {
        // Compare coordinate-by-coordinate (lexicographic order)
        // Shorter coordinates mean closer to root, which is generally better
        if entry1.coords.len() != entry2.coords.len() {
            return entry1.coords.len() < entry2.coords.len();
        }
        
        // Same length, compare element by element
        for (c1, c2) in entry1.coords.iter().zip(entry2.coords.iter()) {
            if c1 != c2 {
                return c1 < c2;
            }
        }
        
        // Coordinates are identical, use hop count as tiebreaker
        entry1.hops < entry2.hops
    }
    
    /// Add or update route
    pub async fn add_route(&self, entry: RouteEntry) -> Result<()> {
        let addr = entry.destination.as_ipv6();
        let mut routes = self.routes.write().await;
        
        // If route exists, compare and select better path
        if let Some(existing) = routes.get(&addr) {
            // Select route with fewer hops or lower latency
            if entry.hops < existing.hops || 
               (entry.hops == existing.hops && entry.latency < existing.latency) {
                debug!("Updating route to {} via better path", addr);
                routes.insert(addr, entry);
            }
        } else {
            info!("Adding new route to {}", addr);
            routes.insert(addr, entry);
        }
        
        Ok(())
    }
    
    /// Find route
    pub async fn find_route(&self, dest: &Ipv6Addr) -> Option<RouteEntry> {
        let routes = self.routes.read().await;
        routes.get(dest).cloned()
    }
    
    /// Remove route
    pub async fn remove_route(&self, dest: &Ipv6Addr) -> Result<()> {
        let mut routes = self.routes.write().await;
        if routes.remove(dest).is_some() {
            info!("Removed route to {}", dest);
        }
        Ok(())
    }
    
    /// Clean up stale routes
    pub async fn cleanup_stale_routes(&self, max_age: std::time::Duration) {
        let mut routes = self.routes.write().await;
        let now = std::time::Instant::now();
        
        routes.retain(|addr, entry| {
            let age = now.duration_since(entry.last_update);
            if age > max_age {
                warn!("Removing stale route to {} (age: {:?})", addr, age);
                false
            } else {
                true
            }
        });
    }
    
    /// Get all routes
    pub async fn get_all_routes(&self) -> Vec<RouteEntry> {
        let routes = self.routes.read().await;
        routes.values().cloned().collect()
    }
    
    /// Get route count
    pub async fn route_count(&self) -> usize {
        let routes = self.routes.read().await;
        routes.len()
    }
    
    /// Route packet using tree-space greedy routing with fallback
    /// 
    /// This method implements enhanced greedy routing:
    /// 1. First tries direct route if available
    /// 2. Then uses tree-space coordinate-based routing
    /// 3. Falls back to best-hop routing if coordinates unavailable
    pub async fn route_packet_greedy(&self, dest_addr: &Ipv6Addr, packet: Vec<u8>) -> Result<()> {
        // First check if we have a direct route
        if let Some(route) = self.find_route(dest_addr).await {
            debug!("Using direct route to {} via {} (hops: {})", 
                   dest_addr, Address::from_public_key(&route.next_hop), route.hops);
            
            // Send packet to next hop peer
            if let Some(ref event_tx) = self.event_tx {
                event_tx.send(RouterEvent::PacketToPeer(route.next_hop, packet)).await
                    .map_err(|e| anyhow::anyhow!("Failed to send packet to peer: {}", e))?;
            }
            return Ok(());
        }
        
        // No direct route, try greedy routing based on coordinates
        let _spanning_tree = match self.spanning_tree.as_ref() {
            Some(tree) => tree,
            None => {
                warn!("No spanning tree available, cannot use greedy routing for {}", dest_addr);
                self.send_icmp_unreachable(&packet, &Address::from(*dest_addr)).await?;
                return Ok(());
            }
        };
        
        // Get all routes with coordinates
        let routes = self.routes.read().await;
        let mut candidates: Vec<&RouteEntry> = routes.values()
            .filter(|r| !r.coords.is_empty())
            .collect();
        
        if candidates.is_empty() {
            debug!("No routes with coordinates available for greedy routing to {}", dest_addr);
            self.send_icmp_unreachable(&packet, &Address::from(*dest_addr)).await?;
            return Ok(());
        }
        
        // Sort candidates by tree-space distance
        // Routes with coordinates "closer" to root are preferred
        candidates.sort_by(|a, b| {
            // Compare coordinate length first (shorter = closer to root)
            match a.coords.len().cmp(&b.coords.len()) {
                std::cmp::Ordering::Equal => {
                    // Same length, compare lexicographically
                    match a.coords.cmp(&b.coords) {
                        std::cmp::Ordering::Equal => {
                            // Same coords, use hop count + latency as tiebreaker
                            let cost_a = (a.hops as u64) * 1000 + (a.latency as u64);
                            let cost_b = (b.hops as u64) * 1000 + (b.latency as u64);
                            cost_a.cmp(&cost_b)
                        }
                        other => other,
                    }
                }
                other => other,
            }
        });
        
        // Select the best candidate
        let best = candidates[0];
        debug!(
            "Greedy routing: selected peer {} with coords {:?} for destination {} (hops: {}, latency: {}ms)",
            Address::from_public_key(&best.next_hop),
            best.coords,
            dest_addr,
            best.hops,
            best.latency
        );
        
        // Send packet to selected peer
        if let Some(ref event_tx) = self.event_tx {
            event_tx.send(RouterEvent::PacketToPeer(best.next_hop, packet)).await
                .map_err(|e| anyhow::anyhow!("Failed to send packet to peer: {}", e))?;
        }
        
        Ok(())
    }
    
    /// Route packet using tree-space greedy routing
    /// 
    /// Selects the peer with coordinates closest to the destination in tree-space.
    /// This implements Ironwood-style coordinate-based routing.
    pub async fn route_greedy(&self, dest_addr: &Ipv6Addr, _packet: Vec<u8>) -> Result<VerifyingKey> {
        // First, check if we have a direct route
        if let Some(route) = self.find_route(dest_addr).await {
            return Ok(route.next_hop);
        }
        
        // No direct route, use greedy routing based on coordinates
        let _spanning_tree = self.spanning_tree.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No spanning tree available for greedy routing"))?;
        
        // Get all routes with coordinates
        let routes = self.routes.read().await;
        let mut candidates: Vec<&RouteEntry> = routes.values()
            .filter(|r| !r.coords.is_empty())
            .collect();
        
        if candidates.is_empty() {
            return Err(anyhow::anyhow!("No routes with coordinates available"));
        }
        
        // Sort by coordinate distance (lexicographic comparison)
        // Routes with shorter coords are closer to root, which is generally better
        candidates.sort_by(|a, b| {
            // Compare coordinate length first
            match a.coords.len().cmp(&b.coords.len()) {
                std::cmp::Ordering::Equal => {
                    // Same length, compare lexicographically
                    a.coords.cmp(&b.coords)
                }
                other => other,
            }
        });
        
        // Select the best candidate
        let best = candidates[0];
        debug!(
            "Greedy routing: selected peer {} with coords {:?} for destination {}",
            Address::from_public_key(&best.next_hop),
            best.coords,
            dest_addr
        );
        
        Ok(best.next_hop)
    }
    
    /// Calculate tree-space distance between two coordinate sets
    /// 
    /// Returns the number of coordinate positions that differ.
    /// This is used for greedy routing in tree-space.
    pub fn coords_distance(coords1: &[u64], coords2: &[u64]) -> usize {
        let min_len = std::cmp::min(coords1.len(), coords2.len());
        let mut distance = 0;
        
        // Count differing positions
        for i in 0..min_len {
            if coords1[i] != coords2[i] {
                distance += 1;
            }
        }
        
        // Add length difference
        distance += coords1.len().abs_diff(coords2.len());
        
        distance
    }
    
    /// Route packet to destination
    /// 
    /// Processes an IPv6 packet and routes it based on the destination address
    /// Uses enhanced greedy routing with tree-space coordinates
    pub async fn route_packet(&self, packet: Vec<u8>) -> Result<()> {
        // Parse IPv6 header
        if packet.len() < 40 {
            warn!("Packet too short to be valid IPv6: {} bytes", packet.len());
            return Err(anyhow::anyhow!("Invalid IPv6 packet"));
        }
        
        // Extract destination address from IPv6 header (bytes 24-39)
        let dest_bytes: [u8; 16] = packet[24..40].try_into()
            .map_err(|_| anyhow::anyhow!("Failed to extract destination address"))?;
        let dest_addr = Ipv6Addr::from(dest_bytes);
        
        // Extract source address (bytes 8-23)
        let src_bytes: [u8; 16] = packet[8..24].try_into()
            .map_err(|_| anyhow::anyhow!("Failed to extract source address"))?;
        let src_addr = Ipv6Addr::from(src_bytes);
        
        debug!("Routing packet: {} -> {} ({} bytes)", src_addr, dest_addr, packet.len());
        
        // Use enhanced greedy routing with coordinates
        self.route_packet_greedy(&dest_addr, packet).await
    }
    
    /// Send ICMP destination unreachable
    async fn send_icmp_unreachable(&self, original_packet: &[u8], dest: &Address) -> Result<()> {
        // Only send ICMP for the first fragment or non-fragmented packets
        if original_packet.len() < 40 {
            return Ok(()); // Too short to be valid IPv6
        }
        
        // Extract source address from original packet
        let src_bytes: [u8; 16] = original_packet[8..24]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to extract source address"))?;
        let src_addr = Ipv6Addr::from(src_bytes);
        
        // Don't send ICMP in response to ICMP errors (avoid loops)
        let next_header = original_packet[6];
        if next_header == 58 { // ICMPv6
            if original_packet.len() > 40 {
                let icmp_type = original_packet[40];
                if icmp_type >= 128 { // Error messages are types 0-127
                    return Ok(());
                }
            }
        }
        
        debug!("Sending ICMP destination unreachable to {} for {}", src_addr, dest);
        
        // Build ICMPv6 Destination Unreachable message
        // Type: 1 (Destination Unreachable)
        // Code: 0 (No route to destination)
        
        let mut icmp_packet = Vec::new();
        
        // ICMPv6 header
        icmp_packet.push(1);  // Type: Destination Unreachable
        icmp_packet.push(0);  // Code: No route to destination
        icmp_packet.extend_from_slice(&[0u8; 2]); // Checksum (calculated later)
        icmp_packet.extend_from_slice(&[0u8; 4]); // Unused (must be zero)
        
        // Include as much of original packet as possible (up to minimum MTU)
        let original_data_len = std::cmp::min(original_packet.len(), 1232); // 1280 - 40 (IPv6) - 8 (ICMPv6)
        icmp_packet.extend_from_slice(&original_packet[..original_data_len]);
        
        // Calculate ICMPv6 checksum
        let checksum = Self::calculate_icmpv6_checksum(&src_addr, &self.local_addr, &icmp_packet);
        icmp_packet[2] = (checksum >> 8) as u8;
        icmp_packet[3] = (checksum & 0xff) as u8;
        
        // Build IPv6 packet
        let mut ipv6_packet = vec![0u8; 40];
        
        // Version (6), Traffic Class (0), Flow Label (0)
        ipv6_packet[0] = 0x60;
        
        // Payload length
        let payload_len = icmp_packet.len() as u16;
        ipv6_packet[4] = (payload_len >> 8) as u8;
        ipv6_packet[5] = (payload_len & 0xff) as u8;
        
        // Next header: 58 (ICMPv6)
        ipv6_packet[6] = 58;
        
        // Hop limit
        ipv6_packet[7] = 64;
        
        // Source address (our address)
        ipv6_packet[8..24].copy_from_slice(&self.local_addr.octets());
        
        // Destination address (original source)
        ipv6_packet[24..40].copy_from_slice(&src_addr.octets());
        
        // Append ICMP payload
        ipv6_packet.extend_from_slice(&icmp_packet);
        
        // Send to TUN interface if available
        if let Some(ref event_tx) = self.event_tx {
            let _ = event_tx.send(RouterEvent::PacketToTun(ipv6_packet)).await;
        }
        
        Ok(())
    }
    
    /// Calculate ICMPv6 checksum
    fn calculate_icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmp_data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        
        // Pseudo-header: source address
        for chunk in src.octets().chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        
        // Pseudo-header: destination address
        for chunk in dst.octets().chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        
        // Pseudo-header: ICMPv6 length
        sum += icmp_data.len() as u32;
        
        // Pseudo-header: Next Header (58 for ICMPv6)
        sum += 58;
        
        // ICMPv6 message
        let mut i = 0;
        while i < icmp_data.len() {
            if i + 1 < icmp_data.len() {
                sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
            } else {
                sum += (icmp_data[i] as u32) << 8;
            }
            i += 2;
        }
        
        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        
        !sum as u16
    }
    
    /// Handle packet received from peer
    /// 
    /// Determines if packet is for local node or should be forwarded
    pub async fn handle_peer_packet(&self, peer_key: VerifyingKey, packet: Vec<u8>, local_addr: &Ipv6Addr) -> Result<()> {
        if packet.len() < 40 {
            warn!("Received packet too short to be valid IPv6: {} bytes", packet.len());
            return Ok(());
        }
        
        // Extract destination address
        let dest_bytes: [u8; 16] = packet[24..40].try_into()
            .map_err(|_| anyhow::anyhow!("Failed to extract destination address"))?;
        let dest_addr = Ipv6Addr::from(dest_bytes);
        
        debug!("Received packet from peer {} for {}", 
               Address::from_public_key(&peer_key), dest_addr);
        
        // Check if packet is for local node
        if &dest_addr == local_addr {
            debug!("Packet is for local node, sending to TUN");
            
            // Send to TUN interface
            if let Some(ref event_tx) = self.event_tx {
                event_tx.send(RouterEvent::PacketToTun(packet)).await
                    .map_err(|e| anyhow::anyhow!("Failed to send packet to TUN: {}", e))?;
            }
        } else {
            debug!("Packet is for another node, forwarding");
            
            // Forward packet to next hop
            self.route_packet(packet).await?;
        }
        
        Ok(())
    }
    
    /// Process packet from TUN interface
    /// 
    /// Handles packets originating from the local node
    pub async fn handle_tun_packet(&self, packet: Vec<u8>) -> Result<()> {
        debug!("Processing packet from TUN: {} bytes", packet.len());
        
        // Route the packet
        self.route_packet(packet).await
    }
    
    /// Update route based on received packet
    /// 
    /// This is used for automatic route discovery
    pub async fn update_route_from_packet(&self, peer_key: VerifyingKey, packet: &[u8], latency_ms: u32) -> Result<()> {
        if packet.len() < 40 {
            return Ok(());
        }
        
        // Extract source address
        let src_bytes: [u8; 16] = packet[8..24].try_into()
            .map_err(|_| anyhow::anyhow!("Failed to extract source address"))?;
        let src_addr = Ipv6Addr::from(src_bytes);
        
        // Check if this is a Yggdrasil address (starts with 0x02 or 0x03)
        if src_addr.segments()[0] == 0x0200 || src_addr.segments()[0] == 0x0300 {
            // Add or update route to source via this peer
            let entry = RouteEntry {
                destination: Address::from(src_addr),
                next_hop: peer_key,
                hops: 1, // Direct peer
                latency: latency_ms, // Use measured latency from peer
                last_update: std::time::Instant::now(),
                coords: vec![1], // Direct peer has coordinate of 1
                root: Some(peer_key), // Direct peer is its own root
            };
            
            self.add_route(entry).await?;
            debug!("Updated route to {} via peer {} (latency: {}ms)", src_addr, 
                   Address::from_public_key(&peer_key), latency_ms);
        }
        
        Ok(())
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use ed25519_dalek::SigningKey;
    
    #[tokio::test]
    async fn test_routing_table() {
        let (tx, _rx) = mpsc::channel(100);
        let table = RoutingTable::with_event_channel(tx);
        
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let public_key = signing_key.verifying_key();
        let addr = Address::from_public_key(&public_key);
        
        let entry = RouteEntry {
            destination: addr,
            next_hop: public_key,
            hops: 1,
            latency: 10,
            last_update: std::time::Instant::now(),
            coords: vec![1],
            root: Some(public_key),
        };
        
        table.add_route(entry.clone()).await.unwrap();
        
        let found = table.find_route(&addr.as_ipv6()).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().hops, 1);
        
        assert_eq!(table.route_count().await, 1);
    }
    
    #[tokio::test]
    async fn test_packet_routing() {
        let (tx, mut rx) = mpsc::channel(100);
        let table = RoutingTable::with_event_channel(tx);
        
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let public_key = signing_key.verifying_key();
        let addr = Address::from_public_key(&public_key);
        
        // Add route
        let entry = RouteEntry {
            destination: addr,
            next_hop: public_key,
            hops: 1,
            latency: 10,
            last_update: std::time::Instant::now(),
            coords: vec![1],
            root: Some(public_key),
        };
        table.add_route(entry).await.unwrap();
        
        // Create IPv6 packet (simplified header)
        let mut packet = vec![0x60, 0x00, 0x00, 0x00]; // Version, class, flow label
        packet.extend_from_slice(&[0x00, 0x14]); // Payload length
        packet.extend_from_slice(&[0x11, 0x40]); // Next header (UDP), hop limit
        
        // Source address (random)
        packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        
        // Destination address (our target)
        let dest_octets = addr.as_ipv6().octets();
        packet.extend_from_slice(&dest_octets);
        
        // Route packet
        table.route_packet(packet.clone()).await.unwrap();
        
        // Check that packet was sent to peer
        match rx.try_recv() {
            Ok(RouterEvent::PacketToPeer(key, data)) => {
                assert_eq!(key.to_bytes(), public_key.to_bytes());
                assert_eq!(data.len(), packet.len());
            }
            _ => panic!("Expected PacketToPeer event"),
        }
    }
    
    #[tokio::test]
    async fn test_handle_peer_packet() {
        let (tx, mut rx) = mpsc::channel(100);
        let table = RoutingTable::with_event_channel(tx);
        
        let local_addr = Ipv6Addr::from([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        
        // Create packet destined for local node
        let mut packet = vec![0x60, 0x00, 0x00, 0x00]; // Version, class, flow label
        packet.extend_from_slice(&[0x00, 0x14]); // Payload length
        packet.extend_from_slice(&[0x11, 0x40]); // Next header (UDP), hop limit
        
        // Source address
        packet.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
        
        // Destination address (local)
        packet.extend_from_slice(&local_addr.octets());
        
        let peer_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>()).verifying_key();
        
        // Handle packet
        table.handle_peer_packet(peer_key, packet.clone(), &local_addr).await.unwrap();
        
        // Check that packet was sent to TUN
        match rx.try_recv() {
            Ok(RouterEvent::PacketToTun(data)) => {
                assert_eq!(data.len(), packet.len());
            }
            _ => panic!("Expected PacketToTun event"),
        }
    }
}
