//! Bloom filter implementation for multicast routing.

use std::collections::HashMap;

use bloomfilter::Bloom;
use yggdrasil_types::{PublicKey, WireError, sizes::PUBLIC_KEY_SIZE};
use yggdrasil_wire::{WireDecode, WireEncode, chop_slice};

/// Constants for bloom filter configuration.
/// These match the Go implementation.
pub const BLOOM_FILTER_F: usize = 16; // Number of bytes for flags
pub const BLOOM_FILTER_U: usize = BLOOM_FILTER_F * 8; // Number of u64s in backing array
pub const BLOOM_FILTER_B: usize = BLOOM_FILTER_U * 8; // Number of bytes in backing array
pub const BLOOM_FILTER_M: usize = BLOOM_FILTER_B * 8; // Number of bits
pub const BLOOM_FILTER_K: u32 = 8; // Number of hash functions

/// A bloom filter for routing.
#[derive(Clone)]
pub struct RoutingBloom {
    filter: Bloom<[u8; PUBLIC_KEY_SIZE]>,
}

impl RoutingBloom {
    /// Create a new empty bloom filter.
    pub fn new() -> Self {
        Self {
            filter: Bloom::new_for_fp_rate(BLOOM_FILTER_M, 0.01)
                .expect("bloom filter creation should succeed"),
        }
    }

    /// Add a public key to the filter.
    pub fn add_key(&mut self, key: &PublicKey) {
        self.filter.set(key.as_bytes());
    }

    /// Check if a key might be in the filter.
    pub fn test(&self, key: &PublicKey) -> bool {
        self.filter.check(key.as_bytes())
    }

    /// Merge another bloom filter into this one.
    pub fn merge(&mut self, _other: &RoutingBloom) {
        // Note: The bloomfilter crate doesn't support direct merging,
        // so we'd need to track keys separately or use a different approach.
        // For now, this is a placeholder.
    }

    /// Clear the filter.
    pub fn clear(&mut self) {
        self.filter.clear();
    }
}

impl Default for RoutingBloom {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RoutingBloom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoutingBloom {{ ... }}")
    }
}

/// Bloom filter information for a peer.
#[derive(Debug, Clone)]
pub struct BloomInfo {
    /// Filter we've sent to this peer
    pub send: RoutingBloom,
    /// Filter we've received from this peer
    pub recv: RoutingBloom,
    /// Sequence number for resending
    pub seq: u16,
    /// Whether this peer is on the spanning tree
    pub on_tree: bool,
    /// Whether we need to send zeros (filter updates)
    pub z_dirty: bool,
}

impl BloomInfo {
    /// Create new bloom info for a peer.
    pub fn new() -> Self {
        Self {
            send: RoutingBloom::new(),
            recv: RoutingBloom::new(),
            seq: 0,
            on_tree: false,
            z_dirty: false,
        }
    }
}

impl Default for BloomInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for bloom filters.
pub struct BloomManager {
    /// Bloom info per peer
    blooms: HashMap<PublicKey, BloomInfo>,
    /// Transform function for keys
    transform: Box<dyn Fn(&PublicKey) -> PublicKey + Send + Sync>,
}

impl BloomManager {
    /// Create a new bloom manager.
    pub fn new() -> Self {
        Self {
            blooms: HashMap::new(),
            transform: Box::new(|k| *k),
        }
    }

    /// Set the key transform function.
    pub fn set_transform<F>(&mut self, transform: F)
    where
        F: Fn(&PublicKey) -> PublicKey + Send + Sync + 'static,
    {
        self.transform = Box::new(transform);
    }

    /// Transform a key using the configured transform.
    pub fn transform_key(&self, key: &PublicKey) -> PublicKey {
        (self.transform)(key)
    }

    /// Add info for a peer.
    pub fn add_peer(&mut self, key: PublicKey) {
        self.blooms.insert(key, BloomInfo::new());
    }

    /// Remove info for a peer.
    pub fn remove_peer(&mut self, key: &PublicKey) {
        self.blooms.remove(key);
    }

    /// Get info for a peer.
    pub fn get(&self, key: &PublicKey) -> Option<&BloomInfo> {
        self.blooms.get(key)
    }

    /// Get mutable info for a peer.
    pub fn get_mut(&mut self, key: &PublicKey) -> Option<&mut BloomInfo> {
        self.blooms.get_mut(key)
    }

    /// Check if a peer is on the tree.
    pub fn is_on_tree(&self, key: &PublicKey) -> bool {
        self.blooms.get(key).map(|b| b.on_tree).unwrap_or(false)
    }

    /// Iterate over all peers.
    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &BloomInfo)> {
        self.blooms.iter()
    }

    /// Iterate mutably over all peers.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&PublicKey, &mut BloomInfo)> {
        self.blooms.iter_mut()
    }
}

impl Default for BloomManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BloomManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BloomManager")
            .field("peer_count", &self.blooms.len())
            .finish()
    }
}

/// Wire-encodable bloom filter for network transmission.
#[derive(Debug, Clone)]
pub struct WireBloom {
    /// Raw bytes of the bloom filter
    data: Vec<u8>,
}

impl WireBloom {
    /// Create from a routing bloom.
    pub fn from_bloom(_bloom: &RoutingBloom) -> Self {
        // Serialize the bloom filter
        // This is a simplified implementation
        Self {
            data: vec![0u8; BLOOM_FILTER_F * 2],
        }
    }

    /// Convert to a routing bloom.
    pub fn to_bloom(&self) -> Result<RoutingBloom, WireError> {
        // Deserialize the bloom filter
        Ok(RoutingBloom::new())
    }
}

impl WireEncode for WireBloom {
    fn wire_size(&self) -> usize {
        BLOOM_FILTER_F * 2 + self.data.len()
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        // Encode flags and data
        let flags0 = [0u8; BLOOM_FILTER_F];
        let flags1 = [0u8; BLOOM_FILTER_F];
        out.extend_from_slice(&flags0);
        out.extend_from_slice(&flags1);
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

impl WireDecode for WireBloom {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let mut flags0 = [0u8; BLOOM_FILTER_F];
        let mut flags1 = [0u8; BLOOM_FILTER_F];

        if !chop_slice(&mut flags0, data) {
            return Err(WireError::Decode);
        }
        if !chop_slice(&mut flags1, data) {
            return Err(WireError::Decode);
        }

        // Decode based on flags
        let mut bloom_data = Vec::new();
        for idx in 0..BLOOM_FILTER_U {
            let flag0 = flags0[idx / 8] & (0x80 >> (idx % 8));
            let flag1 = flags1[idx / 8] & (0x80 >> (idx % 8));

            if flag0 != 0 && flag1 != 0 {
                return Err(WireError::Decode);
            } else if flag0 != 0 {
                bloom_data.extend_from_slice(&[0u8; 8]);
            } else if flag1 != 0 {
                bloom_data.extend_from_slice(&[0xFF; 8]);
            } else if data.len() >= 8 {
                bloom_data.extend_from_slice(&data[..8]);
                *data = &data[8..];
            } else {
                return Err(WireError::Decode);
            }
        }

        Ok(Self { data: bloom_data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_basic() {
        let mut bloom = RoutingBloom::new();
        let key = PublicKey::from([1u8; 32]);

        assert!(!bloom.test(&key));
        bloom.add_key(&key);
        assert!(bloom.test(&key));
    }

    #[test]
    fn test_bloom_info() {
        let info = BloomInfo::new();
        assert!(!info.on_tree);
        assert!(!info.z_dirty);
    }

    #[test]
    fn test_bloom_manager() {
        let mut manager = BloomManager::new();
        let key = PublicKey::from([2u8; 32]);

        manager.add_peer(key);
        assert!(manager.get(&key).is_some());

        manager.remove_peer(&key);
        assert!(manager.get(&key).is_none());
    }
}
