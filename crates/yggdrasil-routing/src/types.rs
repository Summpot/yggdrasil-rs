//! Type definitions for routing.

use std::time::{Duration, Instant};

use yggdrasil_types::{PeerPort, PublicKey, Signature};
use yggdrasil_wire::{RouterSigRes, Traffic};

/// Information about a router node.
#[derive(Debug, Clone)]
pub struct RouterInfo {
    /// Parent node's public key
    pub parent: PublicKey,
    /// Signature response from parent
    pub sig_res: RouterSigRes,
    /// Our signature on the routing info
    pub sig: Signature,
}

impl RouterInfo {
    /// Get a RouterAnnounce for this info.
    pub fn get_announce(&self, key: PublicKey) -> yggdrasil_wire::RouterAnnounce {
        yggdrasil_wire::RouterAnnounce {
            key,
            parent: self.parent,
            sig_res: self.sig_res.clone(),
            sig: self.sig,
        }
    }
}

/// Information about a known path.
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Path from root to destination
    pub path: Vec<PeerPort>,
    /// Sequence number of the path info
    pub seq: u64,
    /// Time the request was last sent
    pub req_time: Instant,
    /// Cached traffic packet for this path
    pub traffic: Option<Box<Traffic>>,
    /// Whether the path is known to be broken
    pub broken: bool,
}

impl PathInfo {
    /// Create a new path info.
    pub fn new(path: Vec<PeerPort>, seq: u64) -> Self {
        Self {
            path,
            seq,
            req_time: Instant::now(),
            traffic: None,
            broken: false,
        }
    }
}

/// Information about a rumored path (before confirmation).
#[derive(Debug)]
pub struct PathRumor {
    /// Cached traffic packet
    pub traffic: Option<Box<Traffic>>,
    /// Time the rumor was last sent
    pub send_time: Instant,
}

impl PathRumor {
    /// Create a new path rumor.
    pub fn new() -> Self {
        Self {
            traffic: None,
            send_time: Instant::now(),
        }
    }
}

impl Default for PathRumor {
    fn default() -> Self {
        Self::new()
    }
}

/// Latency constant for unknown peer latency.
pub const UNKNOWN_LATENCY: Duration = Duration::from_millis(u32::MAX as u64);
