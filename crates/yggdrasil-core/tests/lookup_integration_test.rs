use ed25519_dalek::SigningKey;
use tokio;
/// Integration tests for Bloom filter lookup system
///
/// Tests the complete lookup workflow including:
/// - Lookup manager integration with Core
/// - Bloom filter updates on peer connection
/// - Node discovery across multiple hops
/// - Cache functionality
use yggdrasil_core::{Config, Core, LookupManager};

#[tokio::test]
async fn test_lookup_manager_in_core() {
    // Create a simple config
    let mut config = Config::generate().unwrap();
    config.listen = vec![];
    config.peers = vec![];
    config.if_name = "none".to_string();

    // Create core
    let core = Core::new(config).await.unwrap();

    // Get lookup stats
    let stats = core.get_lookup_stats().await;

    // Initially should have no filters or cache
    assert_eq!(stats.peer_filter_count, 0);
    assert_eq!(stats.cache_size, 0);
    assert_eq!(stats.active_lookup_count, 0);
}

#[tokio::test]
async fn test_lookup_with_multiple_peers() {
    let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
    let lookup_manager = LookupManager::new(local_key);

    // Add 3 peers with different reachable nodes
    let peer1_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
    let peer2_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
    let peer3_key = SigningKey::from_bytes(&[3u8; 32]).verifying_key();

    let target1 = SigningKey::from_bytes(&[10u8; 32]).verifying_key();
    let target2 = SigningKey::from_bytes(&[20u8; 32]).verifying_key();
    let target3 = SigningKey::from_bytes(&[30u8; 32]).verifying_key();

    // Peer1 can reach target1
    lookup_manager.add_reachable_node(peer1_key, target1).await;

    // Peer2 can reach target2
    lookup_manager.add_reachable_node(peer2_key, target2).await;

    // Peer3 can reach target3
    lookup_manager.add_reachable_node(peer3_key, target3).await;

    // Lookup target1 should return peer1
    let result1 = lookup_manager.lookup_node(&target1).await.unwrap();
    assert_eq!(result1, Some(peer1_key));

    // Lookup target2 should return peer2
    let result2 = lookup_manager.lookup_node(&target2).await.unwrap();
    assert_eq!(result2, Some(peer2_key));

    // Lookup target3 should return peer3
    let result3 = lookup_manager.lookup_node(&target3).await.unwrap();
    assert_eq!(result3, Some(peer3_key));

    // Lookup unknown target should return None
    let unknown = SigningKey::from_bytes(&[99u8; 32]).verifying_key();
    let result_unknown = lookup_manager.lookup_node(&unknown).await.unwrap();
    assert_eq!(result_unknown, None);

    // Check stats
    let stats = lookup_manager.get_stats().await;
    assert_eq!(stats.peer_filter_count, 3);
    assert_eq!(stats.cache_size, 3); // 3 successful lookups cached
}

#[tokio::test]
async fn test_lookup_cache_functionality() {
    let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
    let lookup_manager = LookupManager::new(local_key);

    let peer_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
    let target_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

    // Add reachable node
    lookup_manager
        .add_reachable_node(peer_key, target_key)
        .await;

    // First lookup
    let start = std::time::Instant::now();
    let result1 = lookup_manager.lookup_node(&target_key).await.unwrap();
    let first_lookup_time = start.elapsed();

    // Second lookup (should hit cache and be faster)
    let start = std::time::Instant::now();
    let result2 = lookup_manager.lookup_node(&target_key).await.unwrap();
    let cached_lookup_time = start.elapsed();

    assert_eq!(result1, result2);
    assert_eq!(result1, Some(peer_key));

    // Cache hit should be faster (though this might not always be true in tests)
    println!(
        "First lookup: {:?}, Cached lookup: {:?}",
        first_lookup_time, cached_lookup_time
    );

    // Check cache size
    let stats = lookup_manager.get_stats().await;
    assert_eq!(stats.cache_size, 1);
}

#[tokio::test]
async fn test_lookup_cleanup() {
    let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
    let lookup_manager = LookupManager::new(local_key);

    let peer_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
    let target_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

    // Add node and perform lookup
    lookup_manager
        .add_reachable_node(peer_key, target_key)
        .await;
    let _ = lookup_manager.lookup_node(&target_key).await.unwrap();

    // Cache should have 1 entry
    let stats_before = lookup_manager.get_stats().await;
    assert_eq!(stats_before.cache_size, 1);

    // Run cleanup (cache TTL is 5 minutes, so this shouldn't remove anything)
    lookup_manager.cleanup_cache().await;

    let stats_after = lookup_manager.get_stats().await;
    assert_eq!(stats_after.cache_size, 1); // Still there

    // Cleanup expired lookups (none should be expired yet)
    lookup_manager.cleanup_expired_lookups().await;

    let stats_final = lookup_manager.get_stats().await;
    assert_eq!(stats_final.active_lookup_count, 0); // No active lookups
}

#[tokio::test]
async fn test_bloom_filter_false_positives() {
    let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
    let lookup_manager = LookupManager::new(local_key);

    let peer_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();

    // Add 100 random nodes
    for i in 0..100u8 {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = i;
        let node_key = SigningKey::from_bytes(&key_bytes).verifying_key();
        lookup_manager.add_reachable_node(peer_key, node_key).await;
    }

    // Try looking up nodes that weren't added
    let mut false_positives = 0;
    let mut true_negatives = 0;

    for i in 100..200u8 {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = i;
        let test_key = SigningKey::from_bytes(&key_bytes).verifying_key();

        match lookup_manager.lookup_node(&test_key).await.unwrap() {
            Some(_) => false_positives += 1,
            None => true_negatives += 1,
        }
    }

    println!(
        "False positives: {}, True negatives: {}",
        false_positives, true_negatives
    );

    // With 100 keys in the filter, false positive rate should be quite low
    // We expect most lookups for unknown keys to return None
    assert!(
        true_negatives > false_positives,
        "Too many false positives: {} vs {} true negatives",
        false_positives,
        true_negatives
    );

    // False positive rate should be less than 10% for 100 keys
    let fp_rate = false_positives as f64 / 100.0;
    assert!(
        fp_rate < 0.1,
        "False positive rate too high: {:.2}%",
        fp_rate * 100.0
    );
}

#[tokio::test]
async fn test_lookup_self() {
    let local_key = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
    let lookup_manager = LookupManager::new(local_key);

    // Lookup ourselves should return our own key
    let result = lookup_manager.lookup_node(&local_key).await.unwrap();
    assert_eq!(result, Some(local_key));
}
