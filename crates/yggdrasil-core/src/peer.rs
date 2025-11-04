use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use log::{debug, info, warn};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Traffic sample for rate calculation
#[derive(Debug, Clone)]
struct TrafficSample {
    timestamp: Instant,
    bytes: u64,
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's public key
    pub public_key: VerifyingKey,
    /// Connection address
    pub addr: SocketAddr,
    /// Connection type
    pub conn_type: ConnectionType,
    /// Connection state
    pub state: ConnectionState,
    /// Connection established time
    pub connected_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Round-trip time (milliseconds)
    pub rtt: u32,
    /// RX traffic samples for rate calculation
    rx_samples: VecDeque<TrafficSample>,
    /// TX traffic samples for rate calculation
    tx_samples: VecDeque<TrafficSample>,
    /// Cached RX rate (bytes/sec)
    pub rx_rate: u64,
    /// Cached TX rate (bytes/sec)
    pub tx_rate: u64,
    /// Routing coordinates (path to this peer through the network tree)
    pub coords: Vec<u64>,
    /// Root public key (closest root in the spanning tree)
    pub root: Option<VerifyingKey>,
}

/// Connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Persistent connection (configured peer)
    Persistent,
    /// Ephemeral connection (multicast discovery)
    Ephemeral,
    /// Incoming connection
    Incoming,
    /// Outgoing connection
    Outgoing,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Handshaking
    Handshaking,
    /// Ready (can transfer data)
    Ready,
    /// Disconnecting
    Disconnecting,
    /// Disconnected
    Disconnected,
}

/// Peer manager
#[derive(Clone)]
pub struct PeerManager {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    max_peers: usize,
    peer_timeout: Duration,
}

impl PeerManager {
    /// Create new peer manager
    pub fn new(max_peers: usize, peer_timeout: Duration) -> Self {
        PeerManager {
            peers: Arc::new(RwLock::new(HashMap::new())),
            max_peers,
            peer_timeout,
        }
    }

    /// Add peer
    pub async fn add_peer(&self, info: PeerInfo) -> Result<()> {
        let mut peers = self.peers.write().await;

        // Check if maximum connection count exceeded
        if peers.len() >= self.max_peers && !peers.contains_key(&info.addr) {
            warn!(
                "Maximum peer count reached ({}), rejecting new peer",
                self.max_peers
            );
            return Err(anyhow::anyhow!("Too many peers"));
        }

        info!("Adding peer: {} ({})", info.addr, info.public_key_hex());
        peers.insert(info.addr, info);

        Ok(())
    }

    /// Update peer state
    pub async fn update_peer_state(&self, addr: &SocketAddr, state: ConnectionState) -> Result<()> {
        let mut peers = self.peers.write().await;

        if let Some(peer) = peers.get_mut(addr) {
            debug!("Peer {} state: {:?} -> {:?}", addr, peer.state, state);
            peer.state = state;
            peer.last_activity = Instant::now();
            Ok(())
        } else {
            Err(anyhow::anyhow!("Peer not found: {}", addr))
        }
    }

    /// Update peer activity time
    pub async fn update_peer_activity(&self, addr: &SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            peer.last_activity = Instant::now();
        }
    }

    /// Update peer statistics
    pub async fn update_peer_stats(&self, addr: &SocketAddr, sent: u64, received: u64) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            peer.bytes_sent += sent;
            peer.bytes_received += received;
            peer.last_activity = Instant::now();
        }
    }

    /// Remove peer
    pub async fn remove_peer(&self, addr: &SocketAddr) -> Result<()> {
        let mut peers = self.peers.write().await;

        if let Some(peer) = peers.remove(addr) {
            info!("Removed peer: {} ({})", addr, peer.public_key_hex());
            Ok(())
        } else {
            Err(anyhow::anyhow!("Peer not found: {}", addr))
        }
    }

    /// Get peer information
    pub async fn get_peer(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(addr).cloned()
    }

    /// Find peer by address
    pub async fn find_peer_by_addr(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        self.get_peer(addr).await
    }

    /// Find peer by public key
    pub async fn find_peer_by_key(&self, key: &VerifyingKey) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers
            .values()
            .find(|p| p.public_key.to_bytes() == key.to_bytes())
            .cloned()
    }

    /// Get all peers
    pub async fn get_all_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Update RX bytes for a peer
    pub async fn update_peer_rx(&self, addr: &SocketAddr, bytes: u64) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            peer.update_rx_bytes(bytes);
            Ok(())
        } else {
            anyhow::bail!("Peer not found: {}", addr)
        }
    }

    /// Update TX bytes for a peer
    pub async fn update_peer_tx(&self, addr: &SocketAddr, bytes: u64) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            peer.update_tx_bytes(bytes);
            Ok(())
        } else {
            anyhow::bail!("Peer not found: {}", addr)
        }
    }

    /// Update RTT for a peer
    pub async fn update_peer_rtt(&self, addr: &SocketAddr, rtt_ms: u32) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(addr) {
            peer.rtt = rtt_ms;
            peer.last_activity = Instant::now();
            Ok(())
        } else {
            anyhow::bail!("Peer not found: {}", addr)
        }
    }

    /// Get ready peers
    pub async fn get_ready_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.state == ConnectionState::Ready)
            .cloned()
            .collect()
    }

    /// Clean up timed-out peers
    pub async fn cleanup_stale_peers(&self) -> Vec<SocketAddr> {
        let mut peers = self.peers.write().await;
        let now = Instant::now();
        let mut removed = Vec::new();

        peers.retain(|addr, peer| {
            let idle_time = now.duration_since(peer.last_activity);
            if idle_time > self.peer_timeout {
                warn!("Removing idle peer {} (idle for {:?})", addr, idle_time);
                removed.push(*addr);
                false
            } else {
                true
            }
        });

        removed
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> PeerStats {
        let peers = self.peers.read().await;

        let mut stats = PeerStats {
            total: peers.len(),
            ..Default::default()
        };

        for peer in peers.values() {
            match peer.state {
                ConnectionState::Connected | ConnectionState::Ready => stats.connected += 1,
                ConnectionState::Connecting | ConnectionState::Handshaking => stats.connecting += 1,
                _ => {}
            }

            match peer.conn_type {
                ConnectionType::Incoming => stats.incoming += 1,
                ConnectionType::Outgoing => stats.outgoing += 1,
                ConnectionType::Persistent => stats.persistent += 1,
                ConnectionType::Ephemeral => stats.ephemeral += 1,
            }

            stats.bytes_sent += peer.bytes_sent;
            stats.bytes_received += peer.bytes_received;
        }

        stats
    }
}

impl PeerInfo {
    /// Create a new peer info
    pub fn new(public_key: VerifyingKey, addr: SocketAddr, conn_type: ConnectionType) -> Self {
        Self {
            public_key,
            addr,
            conn_type,
            state: ConnectionState::Connecting,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            rtt: 0,
            rx_samples: VecDeque::new(),
            tx_samples: VecDeque::new(),
            rx_rate: 0,
            tx_rate: 0,
            coords: Vec::new(),
            root: None,
        }
    }

    /// Get public key hexadecimal representation
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.to_bytes())
    }

    /// Update routing coordinates
    pub fn update_coords(&mut self, coords: Vec<u64>) {
        self.coords = coords;
    }

    /// Update root node
    pub fn update_root(&mut self, root: VerifyingKey) {
        self.root = Some(root);
    }

    /// Get coordinates
    pub fn get_coords(&self) -> &[u64] {
        &self.coords
    }

    /// Get root node
    pub fn get_root(&self) -> Option<&VerifyingKey> {
        self.root.as_ref()
    }

    /// Update RX bytes and recalculate rate
    pub fn update_rx_bytes(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.last_activity = Instant::now();

        // Add sample
        self.rx_samples.push_back(TrafficSample {
            timestamp: Instant::now(),
            bytes: self.bytes_received,
        });

        // Keep only samples from last 10 seconds
        let cutoff = Instant::now() - Duration::from_secs(10);
        while let Some(sample) = self.rx_samples.front() {
            if sample.timestamp < cutoff {
                self.rx_samples.pop_front();
            } else {
                break;
            }
        }

        // Calculate rate
        self.rx_rate = self.calculate_rate(&self.rx_samples);
    }

    /// Update TX bytes and recalculate rate
    pub fn update_tx_bytes(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.last_activity = Instant::now();

        // Add sample
        self.tx_samples.push_back(TrafficSample {
            timestamp: Instant::now(),
            bytes: self.bytes_sent,
        });

        // Keep only samples from last 10 seconds
        let cutoff = Instant::now() - Duration::from_secs(10);
        while let Some(sample) = self.tx_samples.front() {
            if sample.timestamp < cutoff {
                self.tx_samples.pop_front();
            } else {
                break;
            }
        }

        // Calculate rate
        self.tx_rate = self.calculate_rate(&self.tx_samples);
    }

    /// Calculate transfer rate from samples (bytes/sec)
    fn calculate_rate(&self, samples: &VecDeque<TrafficSample>) -> u64 {
        if samples.len() < 2 {
            return 0;
        }

        let first = samples.front().unwrap();
        let last = samples.back().unwrap();

        let duration_secs = last.timestamp.duration_since(first.timestamp).as_secs_f64();
        if duration_secs < 0.1 {
            return 0;
        }

        let bytes_diff = last.bytes.saturating_sub(first.bytes);
        (bytes_diff as f64 / duration_secs) as u64
    }
}

/// Peer statistics
#[derive(Debug, Default, Clone)]
pub struct PeerStats {
    pub total: usize,
    pub connected: usize,
    pub connecting: usize,
    pub incoming: usize,
    pub outgoing: usize,
    pub persistent: usize,
    pub ephemeral: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[tokio::test]
    async fn test_peer_manager() {
        let manager = PeerManager::new(100, Duration::from_secs(300));

        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let public_key = signing_key.verifying_key();

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let peer = PeerInfo::new(public_key, addr, ConnectionType::Outgoing);

        manager.add_peer(peer).await.unwrap();
        assert_eq!(manager.peer_count().await, 1);

        manager
            .update_peer_state(&addr, ConnectionState::Ready)
            .await
            .unwrap();
        let updated = manager.get_peer(&addr).await.unwrap();
        assert_eq!(updated.state, ConnectionState::Ready);
    }
}
