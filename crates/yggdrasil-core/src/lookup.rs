/// Bloom Filter-based Node Lookup System
/// 
/// Implements Ironwood-style node discovery using Bloom filters.
/// - 8192-bit (1024-byte) filters for efficient memory usage
/// - 8 hash functions per key for ~80-bit collision resistance
/// - Multicast lookups over spanning tree
/// - Constant state per peer (O(1) routing table size)

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use siphasher::sip::SipHasher13;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use log::{debug, info};

/// Bloom filter size in bits (8192 bits = 1024 bytes)
const BLOOM_FILTER_BITS: usize = 8192;
const BLOOM_FILTER_BYTES: usize = BLOOM_FILTER_BITS / 8;

/// Number of hash functions per key
const HASH_FUNCTION_COUNT: usize = 8;

/// Lookup request timeout
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Bloom filter for node reachability
/// 
/// Maintains which nodes are reachable through a specific peer
/// using a space-efficient probabilistic data structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    /// Bit array (1024 bytes = 8192 bits)
    bits: [u8; BLOOM_FILTER_BYTES],
}

impl BloomFilter {
    /// Create an empty Bloom filter
    pub fn new() -> Self {
        Self {
            bits: [0u8; BLOOM_FILTER_BYTES],
        }
    }
    
    /// Add a key to the Bloom filter
    pub fn add_key(&mut self, key: &VerifyingKey) {
        for i in 0..HASH_FUNCTION_COUNT {
            let bit_index = self.hash_key(key, i);
            self.set_bit(bit_index);
        }
    }
    
    /// Check if a key might be in the filter
    /// 
    /// Returns true if the key might be present (with false positive rate).
    /// Returns false if the key is definitely not present.
    pub fn might_contain(&self, key: &VerifyingKey) -> bool {
        for i in 0..HASH_FUNCTION_COUNT {
            let bit_index = self.hash_key(key, i);
            if !self.get_bit(bit_index) {
                return false;
            }
        }
        true
    }
    
    /// Merge another Bloom filter into this one (OR operation)
    pub fn merge(&mut self, other: &BloomFilter) {
        for i in 0..BLOOM_FILTER_BYTES {
            self.bits[i] |= other.bits[i];
        }
    }
    
    /// Hash a key with a specific hash function index
    fn hash_key(&self, key: &VerifyingKey, hash_index: usize) -> usize {
        let mut hasher = SipHasher13::new();
        hash_index.hash(&mut hasher);
        key.as_bytes().hash(&mut hasher);
        let hash = hasher.finish();
        (hash as usize) % BLOOM_FILTER_BITS
    }
    
    /// Set a bit in the filter
    fn set_bit(&mut self, bit_index: usize) {
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        self.bits[byte_index] |= 1 << bit_offset;
    }
    
    /// Get a bit from the filter
    fn get_bit(&self, bit_index: usize) -> bool {
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        (self.bits[byte_index] & (1 << bit_offset)) != 0
    }
    
    /// Calculate the false positive rate for a given number of keys
    /// 
    /// For reference:
    /// - 1 key: ~80-bit collision resistance
    /// - 200 keys: First false positive in 1M network
    /// - 500 keys: Still majority true positives in 1M network
    pub fn false_positive_rate(&self, num_keys: usize) -> f64 {
        let k = HASH_FUNCTION_COUNT as f64;
        let m = BLOOM_FILTER_BITS as f64;
        let n = num_keys as f64;
        
        // Formula: (1 - e^(-kn/m))^k
        let exponent = -(k * n) / m;
        let base = 1.0 - exponent.exp();
        base.powf(k)
    }
    
    /// Encode filter to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bits.to_vec()
    }
    
    /// Decode filter from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BLOOM_FILTER_BYTES {
            anyhow::bail!("Invalid Bloom filter size: {} bytes", bytes.len());
        }
        
        let mut bits = [0u8; BLOOM_FILTER_BYTES];
        bits.copy_from_slice(bytes);
        
        Ok(Self { bits })
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Lookup request state
#[derive(Debug, Clone)]
struct LookupRequest {
    /// Target key we're looking for
    #[allow(dead_code)]
    target_key: VerifyingKey,
    /// When the request was initiated
    timestamp: Instant,
    /// Callback to invoke when found
    result_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<VerifyingKey>>>>,
}

/// Lookup protocol manager
/// 
/// Manages node discovery using Bloom filters and multicast lookups.
pub struct LookupManager {
    /// Local node key
    local_key: VerifyingKey,
    
    /// Local Bloom filter containing our directly reachable nodes
    local_filter: Arc<RwLock<BloomFilter>>,
    
    /// Bloom filters per peer (peer_key -> filter)
    /// Each filter contains all keys reachable through that peer
    peer_filters: Arc<RwLock<HashMap<[u8; 32], BloomFilter>>>,
    
    /// Active lookup requests (target_key -> request)
    active_lookups: Arc<RwLock<HashMap<[u8; 32], LookupRequest>>>,
    
    /// Cache of recent lookup results (target_key -> next_hop_key)
    lookup_cache: Arc<RwLock<HashMap<[u8; 32], (VerifyingKey, Instant)>>>,
}

impl LookupManager {
    /// Create new lookup manager
    pub fn new(local_key: VerifyingKey) -> Self {
        let mut local_filter = BloomFilter::new();
        // Add ourselves to the local filter
        local_filter.add_key(&local_key);
        
        Self {
            local_key,
            local_filter: Arc::new(RwLock::new(local_filter)),
            peer_filters: Arc::new(RwLock::new(HashMap::new())),
            active_lookups: Arc::new(RwLock::new(HashMap::new())),
            lookup_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Update the Bloom filter for a peer
    /// 
    /// This should be called when receiving filter updates from peers.
    pub async fn update_peer_filter(&self, peer_key: VerifyingKey, filter: BloomFilter) {
        let mut filters = self.peer_filters.write().await;
        filters.insert(peer_key.to_bytes(), filter);
        debug!("Updated Bloom filter for peer {}", hex::encode(&peer_key.to_bytes()[..8]));
    }
    
    /// Add a directly reachable node to the Bloom filter for a peer
    pub async fn add_reachable_node(&self, peer_key: VerifyingKey, node_key: VerifyingKey) {
        let mut filters = self.peer_filters.write().await;
        let filter = filters.entry(peer_key.to_bytes()).or_insert_with(BloomFilter::new);
        filter.add_key(&node_key);
        
        // Also add to local filter
        let mut local_filter = self.local_filter.write().await;
        local_filter.add_key(&node_key);
    }
    
    /// Get the local Bloom filter
    pub async fn get_local_filter(&self) -> BloomFilter {
        let filter = self.local_filter.read().await;
        filter.clone()
    }
    
    /// Lookup a node in the network
    /// 
    /// Returns the next-hop peer key to route towards the target,
    /// or None if the target is not found in any Bloom filter.
    pub async fn lookup_node(&self, target_key: &VerifyingKey) -> Result<Option<VerifyingKey>> {
        let target_bytes = target_key.to_bytes();
        
        // Check cache first
        let cache = self.lookup_cache.read().await;
        if let Some((next_hop, timestamp)) = cache.get(&target_bytes) {
            if timestamp.elapsed() < Duration::from_secs(60) {
                debug!("Lookup cache hit for target {}", hex::encode(&target_bytes[..8]));
                return Ok(Some(*next_hop));
            }
        }
        drop(cache);
        
        // Check if target is us
        if target_bytes == self.local_key.to_bytes() {
            return Ok(Some(self.local_key));
        }
        
        // Search Bloom filters
        let filters = self.peer_filters.read().await;
        let mut candidates = Vec::new();
        
        for (peer_key_bytes, filter) in filters.iter() {
            if filter.might_contain(target_key) {
                let peer_key = VerifyingKey::from_bytes(peer_key_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid peer key: {}", e))?;
                candidates.push(peer_key);
            }
        }
        drop(filters);
        
        if candidates.is_empty() {
            debug!("No Bloom filter matches for target {}", hex::encode(&target_bytes[..8]));
            return Ok(None);
        }
        
        // Select best candidate (for now, just use first one)
        // TODO: Use tree-space distance to select closest peer
        let next_hop = candidates[0];
        
        // Update cache
        let mut cache = self.lookup_cache.write().await;
        cache.insert(target_bytes, (next_hop, Instant::now()));
        
        debug!(
            "Lookup found {} candidates for target {}, selected {}",
            candidates.len(),
            hex::encode(&target_bytes[..8]),
            hex::encode(&next_hop.to_bytes()[..8])
        );
        
        Ok(Some(next_hop))
    }
    
    /// Initiate a lookup request (multicast over tree)
    /// 
    /// Returns a channel that will receive the result when found.
    pub async fn start_lookup_request(&self, target_key: VerifyingKey) -> tokio::sync::oneshot::Receiver<VerifyingKey> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        
        let request = LookupRequest {
            target_key,
            timestamp: Instant::now(),
            result_tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        };
        
        let mut lookups = self.active_lookups.write().await;
        lookups.insert(target_key.to_bytes(), request);
        
        info!("Started lookup request for {}", hex::encode(&target_key.to_bytes()[..8]));
        
        rx
    }
    
    /// Handle an incoming lookup request from a peer
    /// 
    /// If we know the target, respond with our key.
    /// If not, propagate to peers whose Bloom filters match.
    pub async fn handle_lookup_request(&self, target_key: VerifyingKey, from_peer: VerifyingKey) -> Result<()> {
        let target_bytes = target_key.to_bytes();
        
        debug!(
            "Handling lookup request for {} from {}",
            hex::encode(&target_bytes[..8]),
            hex::encode(&from_peer.to_bytes()[..8])
        );
        
        // Check if target is us
        if target_bytes == self.local_key.to_bytes() {
            info!("Lookup request matched local node");
            // TODO: Send lookup response back to from_peer
            return Ok(());
        }
        
        // Check Bloom filters and propagate
        let next_hop = self.lookup_node(&target_key).await?;
        if next_hop.is_some() {
            debug!("Propagating lookup request to next hop");
            // TODO: Forward lookup request to next_hop
        }
        
        Ok(())
    }
    
    /// Handle an incoming lookup response
    /// 
    /// Completes the lookup request if we initiated it.
    pub async fn handle_lookup_response(&self, target_key: VerifyingKey, found_at: VerifyingKey) -> Result<()> {
        let target_bytes = target_key.to_bytes();
        
        let mut lookups = self.active_lookups.write().await;
        if let Some(request) = lookups.remove(&target_bytes) {
            info!(
                "Lookup request completed for {} at {}",
                hex::encode(&target_bytes[..8]),
                hex::encode(&found_at.to_bytes()[..8])
            );
            
            // Send result through channel
            if let Some(tx) = request.result_tx.lock().await.take() {
                let _ = tx.send(found_at);
            }
            
            // Update cache
            let mut cache = self.lookup_cache.write().await;
            cache.insert(target_bytes, (found_at, Instant::now()));
        }
        
        Ok(())
    }
    
    /// Clean up expired lookup requests
    pub async fn cleanup_expired_lookups(&self) {
        let mut lookups = self.active_lookups.write().await;
        let before = lookups.len();
        
        lookups.retain(|_, request| {
            request.timestamp.elapsed() < LOOKUP_TIMEOUT
        });
        
        let removed = before - lookups.len();
        if removed > 0 {
            debug!("Cleaned up {} expired lookup requests", removed);
        }
    }
    
    /// Clean up expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.lookup_cache.write().await;
        let before = cache.len();
        
        cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed() < Duration::from_secs(300) // 5 minute cache
        });
        
        let removed = before - cache.len();
        if removed > 0 {
            debug!("Cleaned up {} expired cache entries", removed);
        }
    }
    
    /// Get statistics about the lookup system
    pub async fn get_stats(&self) -> LookupStats {
        let filters = self.peer_filters.read().await;
        let lookups = self.active_lookups.read().await;
        let cache = self.lookup_cache.read().await;
        
        LookupStats {
            peer_filter_count: filters.len(),
            active_lookup_count: lookups.len(),
            cache_size: cache.len(),
        }
    }
}

/// Statistics about the lookup system
#[derive(Debug, Clone)]
pub struct LookupStats {
    pub peer_filter_count: usize,
    pub active_lookup_count: usize,
    pub cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    
    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new();
        let key1 = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let key2 = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        
        filter.add_key(&key1);
        
        assert!(filter.might_contain(&key1));
        // key2 might return true (false positive) but very unlikely
    }
    
    #[test]
    fn test_bloom_filter_merge() {
        let mut filter1 = BloomFilter::new();
        let mut filter2 = BloomFilter::new();
        
        let key1 = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let key2 = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        
        filter1.add_key(&key1);
        filter2.add_key(&key2);
        
        filter1.merge(&filter2);
        
        assert!(filter1.might_contain(&key1));
        assert!(filter1.might_contain(&key2));
    }
    
    #[test]
    fn test_bloom_filter_serialization() {
        let mut filter = BloomFilter::new();
        let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        filter.add_key(&key);
        
        let bytes = filter.to_bytes();
        assert_eq!(bytes.len(), BLOOM_FILTER_BYTES);
        
        let decoded = BloomFilter::from_bytes(&bytes).unwrap();
        assert_eq!(filter, decoded);
        assert!(decoded.might_contain(&key));
    }
    
    #[test]
    fn test_bloom_filter_false_positive_rate() {
        let filter = BloomFilter::new();
        
        // With 1 key, should have ~80-bit collision resistance
        let rate_1 = filter.false_positive_rate(1);
        assert!(rate_1 < 0.0001); // Very low
        
        // With 200 keys, still quite low
        let rate_200 = filter.false_positive_rate(200);
        assert!(rate_200 < 0.01); // < 1%
        
        // With 500 keys, higher but still manageable
        let rate_500 = filter.false_positive_rate(500);
        assert!(rate_500 < 0.05); // < 5%
    }
    
    #[tokio::test]
    async fn test_lookup_manager_basic() {
        let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
        let manager = LookupManager::new(local_key);
        
        // Add a peer with some reachable nodes
        let peer_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let target_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        
        manager.add_reachable_node(peer_key, target_key).await;
        
        // Lookup should find the target through peer_key
        let result = manager.lookup_node(&target_key).await.unwrap();
        assert_eq!(result, Some(peer_key));
    }
    
    #[tokio::test]
    async fn test_lookup_manager_cache() {
        let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
        let manager = LookupManager::new(local_key);
        
        let peer_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let target_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        
        manager.add_reachable_node(peer_key, target_key).await;
        
        // First lookup
        let result1 = manager.lookup_node(&target_key).await.unwrap();
        
        // Second lookup should hit cache
        let result2 = manager.lookup_node(&target_key).await.unwrap();
        
        assert_eq!(result1, result2);
    }
    
    #[tokio::test]
    async fn test_lookup_manager_stats() {
        let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
        let manager = LookupManager::new(local_key);
        
        let peer_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let target_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        
        manager.add_reachable_node(peer_key, target_key).await;
        manager.lookup_node(&target_key).await.unwrap();
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.peer_filter_count, 1);
        assert_eq!(stats.cache_size, 1);
    }
}
