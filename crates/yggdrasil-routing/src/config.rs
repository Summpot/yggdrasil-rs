//! Router configuration.

use std::time::Duration;

use yggdrasil_types::PublicKey;

/// Configuration for the router.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// How often to refresh our own routing info
    pub router_refresh: Duration,
    /// Timeout for routing info from other nodes
    pub router_timeout: Duration,
    /// Delay before sending a keep-alive
    pub peer_keepalive_delay: Duration,
    /// Timeout for peer connections
    pub peer_timeout: Duration,
    /// Maximum message size from peers
    pub peer_max_message_size: u64,
    /// Timeout for path entries
    pub path_timeout: Duration,
    /// Throttle for path lookup requests
    pub path_throttle: Duration,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            router_refresh: Duration::from_secs(4 * 60),
            router_timeout: Duration::from_secs(5 * 60),
            peer_keepalive_delay: Duration::from_secs(1),
            peer_timeout: Duration::from_secs(3),
            peer_max_message_size: 1024 * 1024, // 1 MB
            path_timeout: Duration::from_secs(60),
            path_throttle: Duration::from_secs(1),
        }
    }
}

/// Callbacks for router events.
pub trait RouterCallbacks: Send + Sync + 'static {
    /// Transform a public key for bloom filter matching.
    fn bloom_transform(&self, key: &PublicKey) -> PublicKey {
        *key
    }

    /// Called when a path to a node is discovered.
    fn path_notify(&self, key: &PublicKey);
}

/// Default implementation of router callbacks (no-op).
pub struct DefaultCallbacks;

impl RouterCallbacks for DefaultCallbacks {
    fn path_notify(&self, _key: &PublicKey) {}
}
