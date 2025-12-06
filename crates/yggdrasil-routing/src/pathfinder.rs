//! Pathfinder for discovering routes to destinations.

use std::collections::HashMap;
use std::time::Instant;

use yggdrasil_types::{PeerPort, PrivateKey, PublicKey};
use yggdrasil_wire::{PathNotify, PathNotifyInfo, Traffic};

use crate::RouterConfig;
use crate::types::{PathInfo, PathRumor};

/// Pathfinder manages route discovery and caching.
pub struct Pathfinder {
    /// Our current signed path info
    pub info: PathNotifyInfo,
    /// Known paths to destinations
    pub paths: HashMap<PublicKey, PathInfo>,
    /// Rumors about destinations (before confirmation)
    pub rumors: HashMap<PublicKey, PathRumor>,
    /// Configuration
    config: RouterConfig,
}

impl Pathfinder {
    /// Create a new pathfinder.
    pub fn new(config: RouterConfig) -> Self {
        Self {
            info: PathNotifyInfo {
                seq: 0,
                path: Vec::new(),
                sig: Default::default(),
            },
            paths: HashMap::new(),
            rumors: HashMap::new(),
            config,
        }
    }

    /// Sign our current path info with the given key.
    pub fn sign_info(&mut self, key: &PrivateKey) {
        self.info.sign(key);
    }

    /// Update our path info.
    pub fn update_info(&mut self, path: Vec<PeerPort>, key: &PrivateKey) {
        self.info.seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.info.path = path;
        self.info.sign(key);
    }

    /// Check if we should send a lookup for a destination.
    pub fn should_send_lookup(&self, dest: &PublicKey) -> bool {
        if let Some(info) = self.paths.get(dest) {
            // Don't flood with requests
            if info.broken {
                return true;
            }

            return info.req_time.elapsed() >= self.config.path_throttle;
        }

        true
    }

    /// Check if we should send a lookup using a transformed destination key.
    pub fn should_send_lookup_for(&self, dest: &PublicKey, xform: &PublicKey) -> bool {
        if let Some(info) = self.paths.get(dest) {
            if info.broken {
                return true;
            }

            return info.req_time.elapsed() >= self.config.path_throttle;
        }

        if let Some(rumor) = self.rumors.get(xform) {
            return rumor.send_time.elapsed() >= self.config.path_throttle;
        }

        true
    }

    /// Record that we sent a lookup.
    #[allow(dead_code)]
    pub fn mark_lookup_sent(&mut self, dest: PublicKey) {
        if let Some(info) = self.paths.get_mut(&dest) {
            info.req_time = Instant::now();
        }
    }

    /// Record that we sent a lookup, updating either the known path entry or
    /// a rumor entry for throttling.
    pub fn mark_lookup_sent_for(&mut self, dest: PublicKey, xform: PublicKey) {
        if let Some(info) = self.paths.get_mut(&dest) {
            info.req_time = Instant::now();
            return;
        }

        self.rumors
            .entry(xform)
            .and_modify(|r| r.send_time = Instant::now())
            .or_insert_with(|| {
                let mut r = PathRumor::new();
                r.send_time = Instant::now();
                r
            });
    }

    /// Handle a path notification response.
    pub fn handle_notify(
        &mut self,
        notify: &PathNotify,
        our_key: &PublicKey,
        xform_key: impl Fn(&PublicKey) -> PublicKey,
    ) -> bool {
        // Only accept responses meant for us
        if notify.dest != *our_key {
            return false;
        }

        // Verify the signature
        if !notify.check() {
            return false;
        }

        let source = &notify.source;

        if let Some(existing) = self.paths.get(source) {
            // Check if this is newer
            if notify.info.seq <= existing.seq {
                return false;
            }

            // Check if it actually adds new information
            if existing.path == notify.info.path && existing.seq == notify.info.seq {
                return false;
            }
        } else {
            // Check if we have a rumor for this
            let xform = xform_key(source);
            if !self.rumors.contains_key(&xform) {
                // Accept even if we didn't explicitly request it; we simply
                // won't have any buffered traffic to replay.
            }
        }

        // Accept the path
        let mut path_info = PathInfo::new(notify.info.path.clone(), notify.info.seq);

        // Transfer any cached traffic from rumors
        let xform = xform_key(source);
        if let Some(mut rumor) = self.rumors.remove(&xform) {
            if let Some(mut traffic) = rumor.traffic.take() {
                // The cached traffic may have been stored with a transformed
                // destination key; rewrite it to the actual source key we just
                // learned about so that forwarding succeeds.
                traffic.dest = *source;
                path_info.traffic = Some(traffic);
            }
        }

        self.paths.insert(*source, path_info);
        true
    }

    /// Get the path for a destination, if known.
    pub fn get_path(&self, dest: &PublicKey) -> Option<&Vec<PeerPort>> {
        self.paths
            .get(dest)
            .and_then(|info| if info.broken { None } else { Some(&info.path) })
    }

    /// Check if we have a path to a destination.
    pub fn has_path(&self, dest: &PublicKey) -> bool {
        self.paths.contains_key(dest)
    }

    /// Mark a path as broken.
    pub fn mark_broken(&mut self, dest: &PublicKey) {
        if let Some(info) = self.paths.get_mut(dest) {
            info.broken = true;
        }
    }

    /// Reset the timeout for a path (called when we receive traffic).
    pub fn reset_timeout(&mut self, key: &PublicKey) {
        if let Some(info) = self.paths.get_mut(key) {
            if !info.broken {
                info.req_time = Instant::now();
            }
        }
    }

    /// Remove expired paths.
    pub fn cleanup_expired(&mut self) {
        let timeout = self.config.path_timeout;
        self.paths
            .retain(|_, info| info.req_time.elapsed() < timeout);
        self.rumors
            .retain(|_, rumor| rumor.send_time.elapsed() < timeout);
    }

    /// Start a rumor-based lookup for a destination.
    #[allow(dead_code)]
    pub fn start_rumor(&mut self, _dest: PublicKey, xform: PublicKey) {
        if let Some(rumor) = self.rumors.get_mut(&xform) {
            if rumor.send_time.elapsed() < self.config.path_throttle {
                return;
            }
            rumor.send_time = Instant::now();
        } else {
            let mut rumor = PathRumor::new();
            rumor.send_time = Instant::now();
            self.rumors.insert(xform, rumor);
        }
    }

    /// Cache traffic for a rumored destination.
    pub fn cache_rumor_traffic(&mut self, xform: PublicKey, traffic: Box<Traffic>) {
        let rumor = self.rumors.entry(xform).or_insert_with(PathRumor::new);
        rumor.traffic = Some(traffic);
    }

    /// Take cached traffic from a path.
    pub fn take_cached_traffic(&mut self, dest: &PublicKey) -> Option<Box<Traffic>> {
        self.paths
            .get_mut(dest)
            .and_then(|info| info.traffic.take())
    }
}

impl std::fmt::Debug for Pathfinder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pathfinder")
            .field("known_paths", &self.paths.len())
            .field("active_rumors", &self.rumors.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pathfinder_creation() {
        let config = RouterConfig::default();
        let pf = Pathfinder::new(config);
        assert!(pf.paths.is_empty());
        assert!(pf.rumors.is_empty());
    }

    #[test]
    fn test_should_send_lookup() {
        let config = RouterConfig::default();
        let pf = Pathfinder::new(config);
        let dest = PublicKey::from([1u8; 32]);

        // Should send lookup for unknown destination
        let xform = dest;
        assert!(pf.should_send_lookup_for(&dest, &xform));
    }

    #[test]
    fn test_path_broken() {
        let mut config = RouterConfig::default();
        config.path_timeout = std::time::Duration::from_secs(60);

        let mut pf = Pathfinder::new(config);
        let dest = PublicKey::from([1u8; 32]);

        // Add a path
        pf.paths.insert(dest, PathInfo::new(vec![1, 2, 3], 100));
        assert!(!pf.paths.get(&dest).unwrap().broken);

        // Mark it broken
        pf.mark_broken(&dest);
        assert!(pf.paths.get(&dest).unwrap().broken);
    }
}
