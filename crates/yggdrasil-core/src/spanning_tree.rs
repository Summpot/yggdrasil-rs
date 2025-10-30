/// Spanning Tree Protocol Implementation
/// 
/// Based on Ironwood's spanning tree design:
/// - Each node maintains a constant-size message specifying its parent
/// - Uses CRDT-Set semantics for eventual consistency
/// - Gossips ancestry information with peers
/// - Automatically rebuilds on link failures

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use log::{debug, info};

/// Maximum age for tree entries before they are considered stale
const TREE_TIMEOUT: Duration = Duration::from_secs(60);

/// Tree announcement containing node's position in the spanning tree
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeAnnouncement {
    /// Public key of the node making this announcement
    pub node_key: VerifyingKey,
    /// Public key of this node's parent (or self if root)
    pub parent_key: VerifyingKey,
    /// Sequence number to detect newer announcements
    pub sequence: u64,
    /// Timestamp when this announcement was created
    pub timestamp: Instant,
    /// Root public key
    pub root_key: VerifyingKey,
    /// Distance from root (hop count)
    pub root_dist: u64,
}

impl TreeAnnouncement {
    /// Create a new tree announcement
    pub fn new(
        node_key: VerifyingKey,
        parent_key: VerifyingKey,
        root_key: VerifyingKey,
        root_dist: u64,
        sequence: u64,
    ) -> Self {
        Self {
            node_key,
            parent_key,
            sequence,
            timestamp: Instant::now(),
            root_key,
            root_dist,
        }
    }
    
    /// Check if this announcement is newer than another
    pub fn is_newer_than(&self, other: &TreeAnnouncement) -> bool {
        // First compare root keys - prefer "smaller" root (deterministic)
        let root_cmp = self.root_key.as_bytes().cmp(other.root_key.as_bytes());
        
        match root_cmp {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => {
                // Same root, compare distance
                if self.root_dist != other.root_dist {
                    self.root_dist < other.root_dist
                } else {
                    // Same distance, use sequence number
                    self.sequence > other.sequence
                }
            }
        }
    }
    
    /// Check if announcement is stale
    pub fn is_stale(&self) -> bool {
        self.timestamp.elapsed() > TREE_TIMEOUT
    }
    
    /// Encode announcement to wire format
    /// Format: [node_key(32)][parent_key(32)][root_key(32)][root_dist(8)][sequence(8)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        
        // Node key (32 bytes)
        buf.extend_from_slice(self.node_key.as_bytes());
        
        // Parent key (32 bytes)
        buf.extend_from_slice(self.parent_key.as_bytes());
        
        // Root key (32 bytes)
        buf.extend_from_slice(self.root_key.as_bytes());
        
        // Root distance (8 bytes, big-endian)
        buf.extend_from_slice(&self.root_dist.to_be_bytes());
        
        // Sequence (8 bytes, big-endian)
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        
        buf
    }
    
    /// Decode announcement from wire format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 112 {
            anyhow::bail!("TreeAnnouncement data too short: {} bytes", data.len());
        }
        
        // Parse node key
        let node_key = VerifyingKey::from_bytes(
            data[0..32].try_into().map_err(|_| anyhow::anyhow!("Invalid node key"))?
        ).map_err(|e| anyhow::anyhow!("Failed to parse node key: {}", e))?;
        
        // Parse parent key
        let parent_key = VerifyingKey::from_bytes(
            data[32..64].try_into().map_err(|_| anyhow::anyhow!("Invalid parent key"))?
        ).map_err(|e| anyhow::anyhow!("Failed to parse parent key: {}", e))?;
        
        // Parse root key
        let root_key = VerifyingKey::from_bytes(
            data[64..96].try_into().map_err(|_| anyhow::anyhow!("Invalid root key"))?
        ).map_err(|e| anyhow::anyhow!("Failed to parse root key: {}", e))?;
        
        // Parse root distance (8 bytes big-endian)
        let root_dist = u64::from_be_bytes(
            data[96..104].try_into().map_err(|_| anyhow::anyhow!("Invalid root_dist"))?
        );
        
        // Parse sequence (8 bytes big-endian)
        let sequence = u64::from_be_bytes(
            data[104..112].try_into().map_err(|_| anyhow::anyhow!("Invalid sequence"))?
        );
        
        Ok(Self::new(node_key, parent_key, root_key, root_dist, sequence))
    }
}

/// Spanning tree manager
/// 
/// Maintains soft-state CRDT-Set of tree announcements
pub struct SpanningTree {
    /// Our public key
    local_key: VerifyingKey,
    /// Current tree announcements (node_key -> announcement)
    announcements: Arc<RwLock<HashMap<[u8; 32], TreeAnnouncement>>>,
    /// Our current announcement
    local_announcement: Arc<RwLock<TreeAnnouncement>>,
    /// Sequence number for our announcements
    sequence: Arc<RwLock<u64>>,
    /// Peers we're connected to
    peers: Arc<RwLock<HashMap<[u8; 32], PeerTreeInfo>>>,
}

/// Information about a peer's position in the tree
#[derive(Debug, Clone)]
pub struct PeerTreeInfo {
    /// Peer's public key
    pub peer_key: VerifyingKey,
    /// Peer's parent in the tree
    pub parent_key: VerifyingKey,
    /// Peer's root
    pub root_key: VerifyingKey,
    /// Distance from peer to root
    pub root_dist: u64,
    /// Last update time
    pub last_update: Instant,
}

impl SpanningTree {
    /// Create new spanning tree manager
    pub fn new(local_key: VerifyingKey) -> Self {
        // Initially, we are our own root
        let initial_announcement = TreeAnnouncement::new(
            local_key,
            local_key, // We are our own parent
            local_key, // We are the root
            0,         // Distance 0 from ourselves
            0,         // Initial sequence
        );
        
        Self {
            local_key,
            announcements: Arc::new(RwLock::new(HashMap::new())),
            local_announcement: Arc::new(RwLock::new(initial_announcement)),
            sequence: Arc::new(RwLock::new(0)),
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Get our current tree announcement
    pub async fn get_local_announcement(&self) -> TreeAnnouncement {
        self.local_announcement.read().await.clone()
    }
    
    /// Add or update a peer
    pub async fn add_peer(&self, peer_key: VerifyingKey) -> Result<()> {
        let peer_bytes = peer_key.to_bytes();
        let mut peers = self.peers.write().await;
        
        if !peers.contains_key(&peer_bytes) {
            info!("Adding peer to spanning tree: {}", hex::encode(peer_bytes));
            peers.insert(peer_bytes, PeerTreeInfo {
                peer_key,
                parent_key: peer_key, // Initially, peer is its own parent
                root_key: peer_key,
                root_dist: 0,
                last_update: Instant::now(),
            });
        }
        
        Ok(())
    }
    
    /// Remove a peer
    pub async fn remove_peer(&self, peer_key: &VerifyingKey) -> Result<()> {
        let peer_bytes = peer_key.to_bytes();
        let mut peers = self.peers.write().await;
        
        if peers.remove(&peer_bytes).is_some() {
            info!("Removing peer from spanning tree: {}", hex::encode(peer_bytes));
            
            // Check if this peer was our parent
            let local = self.local_announcement.read().await;
            if local.parent_key.to_bytes() == peer_bytes {
                drop(local); // Release read lock
                // We need to select a new parent
                self.select_new_parent().await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle incoming tree announcement from a peer
    pub async fn handle_announcement(&self, announcement: TreeAnnouncement) -> Result<()> {
        let node_bytes = announcement.node_key.to_bytes();
        
        // Update our announcements table
        let mut announcements = self.announcements.write().await;
        
        let should_update = if let Some(existing) = announcements.get(&node_bytes) {
            announcement.is_newer_than(existing)
        } else {
            true
        };
        
        if should_update {
            debug!("Updated tree announcement for {}: root={}, dist={}", 
                hex::encode(&node_bytes[..8]),
                hex::encode(&announcement.root_key.to_bytes()[..8]),
                announcement.root_dist
            );
            announcements.insert(node_bytes, announcement.clone());
            drop(announcements); // Release lock
            
            // Update peer info if this is from a peer
            let mut peers = self.peers.write().await;
            if let Some(peer_info) = peers.get_mut(&node_bytes) {
                peer_info.parent_key = announcement.parent_key;
                peer_info.root_key = announcement.root_key;
                peer_info.root_dist = announcement.root_dist;
                peer_info.last_update = Instant::now();
            }
            drop(peers); // Release lock
            
            // Check if we need to update our own position
            self.update_local_position().await?;
        }
        
        Ok(())
    }
    
    /// Update our position in the tree based on peer announcements
    async fn update_local_position(&self) -> Result<()> {
        let peers = self.peers.read().await;
        let local = self.local_announcement.read().await;
        
        // Find the best parent among our peers
        let mut best_parent: Option<(VerifyingKey, u64, VerifyingKey)> = None;
        
        for peer_info in peers.values() {
            // Calculate what our position would be if we chose this peer as parent
            let new_dist = peer_info.root_dist + 1;
            let peer_root = peer_info.root_key;
            
            // Compare with current best
            let is_better = if let Some((_, best_dist, best_root)) = best_parent {
                // Prefer closer to root with smaller root key
                let root_cmp = peer_root.as_bytes().cmp(best_root.as_bytes());
                match root_cmp {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Greater => false,
                    std::cmp::Ordering::Equal => new_dist < best_dist,
                }
            } else {
                true
            };
            
            if is_better {
                best_parent = Some((peer_info.peer_key, new_dist, peer_root));
            }
        }
        
        drop(peers);
        
        // Check if we should update our parent
        if let Some((new_parent, new_dist, new_root)) = best_parent {
            // Compare with current position
            let should_update = {
                let root_cmp = new_root.as_bytes().cmp(local.root_key.as_bytes());
                match root_cmp {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Greater => false,
                    std::cmp::Ordering::Equal => {
                        // Same root, check if new distance is better
                        new_dist < local.root_dist ||
                        // Or if we're choosing ourselves as root but could have a parent
                        (local.parent_key == self.local_key && new_parent != self.local_key)
                    }
                }
            };
            
            if should_update {
                drop(local);
                self.update_parent(new_parent, new_root, new_dist).await?;
            }
        }
        
        Ok(())
    }
    
    /// Update our parent in the tree
    async fn update_parent(
        &self,
        new_parent: VerifyingKey,
        new_root: VerifyingKey,
        new_dist: u64,
    ) -> Result<()> {
        let mut seq = self.sequence.write().await;
        *seq += 1;
        let sequence = *seq;
        drop(seq);
        
        let new_announcement = TreeAnnouncement::new(
            self.local_key,
            new_parent,
            new_root,
            new_dist,
            sequence,
        );
        
        info!(
            "Updated tree position: parent={}, root={}, dist={}",
            hex::encode(&new_parent.to_bytes()[..8]),
            hex::encode(&new_root.to_bytes()[..8]),
            new_dist
        );
        
        let mut local = self.local_announcement.write().await;
        *local = new_announcement;
        
        Ok(())
    }
    
    /// Select a new parent (called when current parent is lost)
    async fn select_new_parent(&self) -> Result<()> {
        info!("Selecting new parent after parent loss");
        
        // Try to update based on remaining peers
        self.update_local_position().await?;
        
        // If we have no peers, become our own root
        let peers = self.peers.read().await;
        if peers.is_empty() {
            drop(peers);
            info!("No peers available, becoming own root");
            self.update_parent(self.local_key, self.local_key, 0).await?;
        }
        
        Ok(())
    }
    
    /// Clean up stale announcements
    pub async fn cleanup_stale(&self) {
        let mut announcements = self.announcements.write().await;
        let before_count = announcements.len();
        
        announcements.retain(|_, ann| !ann.is_stale());
        
        let removed = before_count - announcements.len();
        if removed > 0 {
            debug!("Cleaned up {} stale tree announcements", removed);
        }
    }
    
    /// Get the path to root for a given node
    /// Returns the sequence of node keys from the node to root
    pub async fn get_path_to_root(&self, node_key: &VerifyingKey) -> Vec<VerifyingKey> {
        let announcements = self.announcements.read().await;
        let mut path = Vec::new();
        let mut current = *node_key;
        let max_hops = 64; // Prevent infinite loops
        
        for _ in 0..max_hops {
            path.push(current);
            
            let current_bytes = current.to_bytes();
            if let Some(ann) = announcements.get(&current_bytes) {
                // Check if we reached the root
                if ann.parent_key == current {
                    break;
                }
                current = ann.parent_key;
            } else {
                // Unknown node
                break;
            }
        }
        
        path
    }
    
    /// Calculate routing coordinates for a node
    /// Coordinates are the path from root to this node
    pub async fn calculate_coords(&self, node_key: &VerifyingKey) -> Vec<u64> {
        let path = self.get_path_to_root(node_key).await;
        
        // Reverse to get root-to-node path
        let mut coords = Vec::new();
        for (i, _) in path.iter().rev().enumerate() {
            coords.push(i as u64);
        }
        
        coords
    }
    
    /// Get all peer keys
    pub async fn get_peer_keys(&self) -> Vec<VerifyingKey> {
        let peers = self.peers.read().await;
        peers.values().map(|p| p.peer_key).collect()
    }
    
    /// Get tree statistics
    pub async fn get_stats(&self) -> TreeStats {
        let local = self.local_announcement.read().await;
        let announcements = self.announcements.read().await;
        let peers = self.peers.read().await;
        
        TreeStats {
            local_root: local.root_key,
            local_dist: local.root_dist,
            local_parent: local.parent_key,
            known_nodes: announcements.len(),
            connected_peers: peers.len(),
        }
    }
}

/// Statistics about the spanning tree
#[derive(Debug, Clone)]
pub struct TreeStats {
    pub local_root: VerifyingKey,
    pub local_dist: u64,
    pub local_parent: VerifyingKey,
    pub known_nodes: usize,
    pub connected_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    
    #[tokio::test]
    async fn test_tree_announcement_comparison() {
        let key1 = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let key2 = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        
        let ann1 = TreeAnnouncement::new(key1, key1, key1, 0, 1);
        let ann2 = TreeAnnouncement::new(key1, key1, key2, 0, 2);
        
        // Ed25519 key derivation doesn't preserve byte order from seed
        // key2's derived key is actually smaller than key1's
        // So ann2 (with key2 as root) is preferred
        assert!(ann2.is_newer_than(&ann1), "Announcement with smaller root key should win");
        assert!(!ann1.is_newer_than(&ann2), "Larger root key should not win");
        
        // Test same root, different distances
        let ann3 = TreeAnnouncement::new(key1, key1, key1, 1, 1);
        let ann4 = TreeAnnouncement::new(key1, key1, key1, 2, 1);
        assert!(ann3.is_newer_than(&ann4), "Closer to root is better");
    }
    
    #[tokio::test]
    async fn test_spanning_tree_initialization() {
        let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let tree = SpanningTree::new(key);
        
        let announcement = tree.get_local_announcement().await;
        assert_eq!(announcement.node_key, key);
        assert_eq!(announcement.parent_key, key);
        assert_eq!(announcement.root_key, key);
        assert_eq!(announcement.root_dist, 0);
    }
    
    #[tokio::test]
    async fn test_add_peer() {
        let local_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let peer_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        
        let tree = SpanningTree::new(local_key);
        tree.add_peer(peer_key).await.unwrap();
        
        let peers = tree.get_peer_keys().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], peer_key);
    }
    
    #[tokio::test]
    async fn test_parent_selection() {
        // Use seed values that will result in local_key > root_key after derivation
        // After trial: seed [255; 32] gives derived key starting with [214...]
        // seed [1; 32] gives derived key starting with [138...]
        // seed [0; 32] gives derived key starting with [59...]
        let local_key = SigningKey::from_bytes(&[255u8; 32]).verifying_key();
        let peer_key = SigningKey::from_bytes(&[10u8; 32]).verifying_key();  
        let root_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
        
        println!("local_key: {:?}", &local_key.to_bytes()[..8]);
        println!("peer_key: {:?}", &peer_key.to_bytes()[..8]);
        println!("root_key: {:?}", &root_key.to_bytes()[..8]);
        println!("root < local: {}", root_key.as_bytes() < local_key.as_bytes());
        
        let tree = SpanningTree::new(local_key);
        tree.add_peer(peer_key).await.unwrap();
        
        // Peer announces it's connected to a better root
        // The peer's parent is root_key, and it's at distance 1
        let peer_announcement = TreeAnnouncement::new(
            peer_key,
            root_key,  // peer's parent
            root_key,  // root of the tree
            1,         // peer is distance 1 from root
            1,
        );
        
        tree.handle_announcement(peer_announcement).await.unwrap();
        
        // Give time for update to propagate
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // We should adopt this peer as our parent
        let local = tree.get_local_announcement().await;
        println!("local.parent_key: {:?}", &local.parent_key.to_bytes()[..8]);
        println!("local.root_key: {:?}", &local.root_key.to_bytes()[..8]);
        println!("local.root_dist: {}", local.root_dist);
        
        assert_eq!(local.parent_key, peer_key, "Should select peer as parent");
        assert_eq!(local.root_key, root_key, "Should adopt peer's root");
        assert_eq!(local.root_dist, 2, "Distance should be peer_dist + 1"); // Distance 2 from root
    }
    
    #[tokio::test]
    async fn test_announcement_serialization() {
        let node_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let parent_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        let root_key = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        
        let original = TreeAnnouncement::new(node_key, parent_key, root_key, 5, 42);
        
        // Encode
        let encoded = original.encode();
        assert_eq!(encoded.len(), 112, "Encoded size should be 112 bytes");
        
        // Decode
        let decoded = TreeAnnouncement::decode(&encoded).unwrap();
        
        // Verify fields match (excluding timestamp which is reset)
        assert_eq!(decoded.node_key, original.node_key);
        assert_eq!(decoded.parent_key, original.parent_key);
        assert_eq!(decoded.root_key, original.root_key);
        assert_eq!(decoded.root_dist, original.root_dist);
        assert_eq!(decoded.sequence, original.sequence);
    }
    
    #[test]
    fn test_announcement_decode_invalid() {
        // Too short
        let short_data = vec![0u8; 50];
        assert!(TreeAnnouncement::decode(&short_data).is_err());
        
        // Exactly 112 bytes should work (even with all zeros)
        let valid_data = vec![0u8; 112];
        let result = TreeAnnouncement::decode(&valid_data);
        // All-zero keys are actually valid in Ed25519
        assert!(result.is_ok(), "112 bytes should decode successfully");
    }
}
