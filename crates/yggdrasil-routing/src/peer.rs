//! Peer management for routing.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use yggdrasil_types::{PeerPort, PublicKey};

use crate::UNKNOWN_LATENCY;

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's public key
    pub key: PublicKey,
    /// Assigned port for this peer
    pub port: PeerPort,
    /// Priority of this peer link (lower is better)
    pub priority: u8,
    /// Order in which peer was connected (for tie-breaking)
    pub order: u64,
    /// Current latency estimate
    pub latency: Duration,
    /// Time the last signature request was sent
    pub sig_req_sent: Option<Instant>,
    /// Whether the writer is ready for more traffic
    pub ready: bool,
}

impl PeerInfo {
    /// Create new peer info.
    pub fn new(key: PublicKey, port: PeerPort, priority: u8, order: u64) -> Self {
        Self {
            key,
            port,
            priority,
            order,
            latency: UNKNOWN_LATENCY,
            sig_req_sent: None,
            ready: true,
        }
    }

    /// Update the latency estimate with a new RTT measurement.
    pub fn update_latency(&mut self, rtt: Duration) {
        if self.latency == UNKNOWN_LATENCY {
            // Start new links with a penalty for stability
            self.latency = rtt * 2;
        } else {
            // Exponentially weighted moving average
            let prev = self.latency;
            self.latency = self.latency * 7 / 8;
            self.latency += std::cmp::min(rtt, prev * 2) / 8;
        }
    }

    /// Get the cost metric for routing decisions.
    pub fn cost(&self) -> u64 {
        // Cost must be non-zero for multiplication/division
        std::cmp::max(1, self.latency.as_millis() as u64)
    }
}

/// Handle for sending messages to a peer.
#[derive(Debug, Clone)]
pub struct PeerHandle {
    /// Channel for sending packets
    pub tx: mpsc::Sender<PeerMessage>,
}

/// Messages that can be sent to a peer.
#[derive(Debug)]
pub enum PeerMessage {
    /// Send a raw packet
    SendPacket(Vec<u8>),
    /// Close the connection
    Close,
}

/// Manager for connected peers.
pub struct PeerManager {
    /// Connected peers by public key
    peers: HashMap<PublicKey, HashMap<PeerPort, PeerInfo>>,
    /// Port assignments
    ports: HashMap<PeerPort, PublicKey>,
    /// Connection order counter
    order: u64,
    /// Next available port
    next_port: PeerPort,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            ports: HashMap::new(),
            order: 0,
            next_port: 1, // Skip port 0
        }
    }

    /// Allocate a port for a new peer.
    fn allocate_port(&mut self, key: &PublicKey) -> PeerPort {
        // Check if we already have a port for this key
        if let Some(key_peers) = self.peers.get(key) {
            if let Some((port, _)) = key_peers.iter().next() {
                return *port;
            }
        }

        // Find an unused port
        loop {
            let port = self.next_port;
            self.next_port += 1;
            if !self.ports.contains_key(&port) {
                return port;
            }
        }
    }

    /// Add a new peer connection.
    pub fn add_peer(&mut self, key: PublicKey, priority: u8) -> PeerInfo {
        let port = self.allocate_port(&key);
        let order = self.order;
        self.order += 1;

        let info = PeerInfo::new(key, port, priority, order);

        self.peers
            .entry(key)
            .or_default()
            .insert(port, info.clone());
        self.ports.insert(port, key);

        PeerInfo::new(key, port, priority, order)
    }

    /// Remove a peer connection.
    pub fn remove_peer(&mut self, key: &PublicKey, port: PeerPort) -> bool {
        if let Some(key_peers) = self.peers.get_mut(key) {
            if key_peers.remove(&port).is_some() {
                if key_peers.is_empty() {
                    self.peers.remove(key);
                    self.ports.remove(&port);
                }
                return true;
            }
        }
        false
    }

    /// Get peer info by key.
    pub fn get_by_key(&self, key: &PublicKey) -> Option<&HashMap<PeerPort, PeerInfo>> {
        self.peers.get(key)
    }

    /// Get peer info by port.
    pub fn get_by_port(&self, port: PeerPort) -> Option<&PeerInfo> {
        self.ports
            .get(&port)
            .and_then(|key| self.peers.get(key))
            .and_then(|peers| peers.get(&port))
    }

    /// Get mutable peer info.
    pub fn get_mut(&mut self, key: &PublicKey, port: PeerPort) -> Option<&mut PeerInfo> {
        self.peers
            .get_mut(key)
            .and_then(|peers| peers.get_mut(&port))
    }

    /// Get the key for a port.
    pub fn key_for_port(&self, port: PeerPort) -> Option<PublicKey> {
        self.ports.get(&port).copied()
    }

    /// Iterate over all peers.
    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &HashMap<PeerPort, PeerInfo>)> {
        self.peers.iter()
    }

    /// Check if we have any connection to a key.
    pub fn is_connected(&self, key: &PublicKey) -> bool {
        self.peers.contains_key(key)
    }

    /// Get the number of unique peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the number of total connections.
    pub fn connection_count(&self) -> usize {
        self.peers.values().map(|p| p.len()).sum()
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("peer_count", &self.peer_count())
            .field("connection_count", &self.connection_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_add_remove() {
        let mut manager = PeerManager::new();
        let key = PublicKey::from([1u8; 32]);

        let info = manager.add_peer(key, 0);
        assert!(manager.is_connected(&key));
        assert_eq!(manager.peer_count(), 1);

        let removed = manager.remove_peer(&key, info.port);
        assert!(removed);
        assert!(!manager.is_connected(&key));
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_peer_latency_update() {
        let mut info = PeerInfo::new(PublicKey::from([0u8; 32]), 1, 0, 0);
        assert_eq!(info.latency, UNKNOWN_LATENCY);

        info.update_latency(Duration::from_millis(100));
        assert!(info.latency < UNKNOWN_LATENCY);

        // Latency should stabilize with consistent measurements
        for _ in 0..10 {
            info.update_latency(Duration::from_millis(100));
        }
    }

    #[test]
    fn test_port_allocation() {
        let mut manager = PeerManager::new();
        let key1 = PublicKey::from([1u8; 32]);
        let key2 = PublicKey::from([2u8; 32]);

        let info1 = manager.add_peer(key1, 0);
        let info2 = manager.add_peer(key2, 0);

        // Different keys should get different ports
        assert_ne!(info1.port, info2.port);

        // Same key should reuse the same port
        let info1b = manager.add_peer(key1, 1);
        assert_eq!(info1.port, info1b.port);
    }
}
