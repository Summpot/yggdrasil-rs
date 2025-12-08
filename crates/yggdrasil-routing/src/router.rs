//! Core router implementation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use yggdrasil_address::{self, Address};
use yggdrasil_types::{PeerPort, PrivateKey, PublicKey, Signature};
use yggdrasil_wire::{PathNotify, RouterAnnounce, RouterSigReq, RouterSigRes, Traffic};

use crate::bloom::BloomManager;
use crate::config::{RouterCallbacks, RouterConfig};
use crate::pathfinder::Pathfinder;
use crate::peer::{PeerInfo, PeerManager};
use crate::types::RouterInfo;

/// The main router struct.
pub struct Router {
    /// Our private key
    private_key: PrivateKey,
    /// Our public key
    public_key: PublicKey,
    /// Configuration
    #[allow(dead_code)]
    config: RouterConfig,
    /// Callbacks
    #[allow(dead_code)]
    callbacks: Arc<dyn RouterCallbacks>,
    /// Peer manager
    peers: PeerManager,
    /// Bloom filter manager
    blooms: BloomManager,
    /// Pathfinder
    pathfinder: Pathfinder,
    /// Router info by public key
    infos: HashMap<PublicKey, RouterInfo>,
    /// Peer ancestry info
    ancestries: HashMap<PublicKey, Vec<PublicKey>>,
    /// Cached paths
    path_cache: HashMap<PublicKey, Vec<PeerPort>>,
    /// Pending signature requests
    requests: HashMap<PublicKey, RouterSigReq>,
    /// Received signature responses
    responses: HashMap<PublicKey, RouterSigRes>,
    /// Response sequence tracking
    res_seqs: HashMap<PublicKey, u64>,
    /// Response sequence counter
    res_seq_ctr: u64,
    /// What we've sent to each peer
    sent: HashMap<PublicKey, HashSet<PublicKey>>,
    /// Whether we need to refresh our info
    refresh: bool,
    /// Whether we should try to become root (stage 1)
    do_root1: bool,
    /// Whether we should try to become root (stage 2)
    do_root2: bool,
}

impl Router {
    /// Create a new router.
    pub fn new(
        private_key: PrivateKey,
        config: RouterConfig,
        callbacks: Arc<dyn RouterCallbacks>,
    ) -> Self {
        let public_key = private_key.public_key();

        // Configure bloom transformation using callbacks so upper layers can
        // control how partial keys are matched (e.g., subnet-derived keys for
        // address lookups).
        let callbacks_for_bloom = Arc::clone(&callbacks);
        let mut blooms = BloomManager::new();
        blooms.set_transform(move |k| callbacks_for_bloom.bloom_transform(k));

        Self {
            private_key,
            public_key,
            config: config.clone(),
            callbacks,
            peers: PeerManager::new(),
            blooms,
            pathfinder: Pathfinder::new(config),
            infos: HashMap::new(),
            ancestries: HashMap::new(),
            path_cache: HashMap::new(),
            requests: HashMap::new(),
            responses: HashMap::new(),
            res_seqs: HashMap::new(),
            res_seq_ctr: 0,
            sent: HashMap::new(),
            refresh: false,
            do_root1: false,
            do_root2: true, // Start by trying to become root
        }
    }

    /// Get our public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Apply the configured bloom/key transformation.
    pub fn transform_key(&self, key: &PublicKey) -> PublicKey {
        self.blooms.transform_key(key)
    }

    /// Add a peer to the router with an explicit port assignment.
    pub fn add_peer_with_port(&mut self, key: PublicKey, port: PeerPort, priority: u8) -> PeerInfo {
        // Add to peer manager
        let info = self.peers.add_peer_with_port(key, port, priority);

        // Initialize tracking structures
        if !self.sent.contains_key(&key) {
            self.sent.insert(key, HashSet::new());
            self.blooms.add_peer(key);
        }

        // Create and send a signature request
        let req = self.new_sig_req();
        self.requests.insert(key, req.clone());

        info
    }

    /// Add a peer to the router, allocating a port automatically.
    pub fn add_peer(&mut self, key: PublicKey, priority: u8) -> PeerInfo {
        let port = self.peers.allocate_port(&key);
        self.add_peer_with_port(key, port, priority)
    }

    /// Determine whether we should send a lookup for the given destination
    /// using the configured transform.
    pub fn should_send_lookup(&self, dest: &PublicKey) -> bool {
        let xform = self.transform_key(dest);
        self.pathfinder.should_send_lookup_for(dest, &xform)
    }

    /// Determine whether we should send a lookup for a pre-transformed key.
    pub fn should_send_lookup_for(&self, dest: &PublicKey, xform: &PublicKey) -> bool {
        self.pathfinder.should_send_lookup_for(dest, xform)
    }

    /// Record that we sent a lookup (throttling) for the given destination.
    #[allow(dead_code)]
    pub fn mark_lookup_sent(&mut self, dest: PublicKey) {
        let xform = self.transform_key(&dest);
        self.pathfinder.mark_lookup_sent_for(dest, xform);
    }

    /// Record that we sent a lookup using a precomputed transform.
    pub fn mark_lookup_sent_for(&mut self, dest: PublicKey, xform: PublicKey) {
        self.pathfinder.mark_lookup_sent_for(dest, xform);
    }

    /// Cache traffic while waiting for a path lookup response.
    pub fn cache_rumor_traffic(&mut self, xform: PublicKey, traffic: Traffic) {
        self.pathfinder
            .cache_rumor_traffic(xform, Box::new(traffic));
    }

    /// Take cached traffic for a destination (if any).
    pub fn take_cached_traffic(&mut self, dest: &PublicKey) -> Option<Box<Traffic>> {
        self.pathfinder.take_cached_traffic(dest)
    }

    /// Handle a PathNotify destined for us, returning any buffered traffic
    /// that should now be forwarded.
    pub fn handle_path_notify(&mut self, notify: &PathNotify) -> Option<Box<Traffic>> {
        let transform = {
            let blooms = &self.blooms;
            move |k: &PublicKey| blooms.transform_key(k)
        };

        if self
            .pathfinder
            .handle_notify(notify, &self.public_key, transform)
        {
            self.callbacks.path_notify(&notify.source);
            return self.pathfinder.take_cached_traffic(&notify.source);
        }

        None
    }

    /// Mark a path as broken in the pathfinder state.
    pub fn mark_path_broken(&mut self, dest: &PublicKey) {
        self.pathfinder.mark_broken(dest);
    }

    /// Remove a peer from the router.
    pub fn remove_peer(&mut self, key: &PublicKey, port: PeerPort) {
        if self.peers.remove_peer(key, port) {
            // If no more connections to this key, clean up
            if !self.peers.is_connected(key) {
                self.sent.remove(key);
                self.requests.remove(key);
                self.responses.remove(key);
                self.res_seqs.remove(key);
                self.ancestries.remove(key);
                self.path_cache.remove(key);
                self.blooms.remove_peer(key);
            }
        }
    }

    /// Create a new signature request.
    fn new_sig_req(&self) -> RouterSigReq {
        let seq = self
            .infos
            .get(&self.public_key)
            .map(|i| i.sig_res.req.seq + 1)
            .unwrap_or(1);

        // Generate a cryptographically secure random nonce
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = u64::from_be_bytes(nonce_bytes);

        RouterSigReq::new(seq, nonce)
    }

    /// Handle a signature request from a peer.
    pub fn handle_sig_request(&self, peer_key: &PublicKey, req: &RouterSigReq) -> RouterSigRes {
        let port = self
            .peers
            .get_by_key(peer_key)
            .and_then(|peers| peers.values().next())
            .map(|p| p.port)
            .unwrap_or(0);

        let mut res = RouterSigRes {
            req: req.clone(),
            port,
            psig: Signature::default(),
        };

        // Sign the response
        let msg = res.bytes_for_sig(&self.public_key, peer_key);
        res.psig = self.private_key.sign(&msg);

        res
    }

    /// Handle a signature response from a peer.
    pub fn handle_sig_response(
        &mut self,
        peer_key: &PublicKey,
        res: &RouterSigRes,
        rtt: Duration,
    ) {
        // Verify the response matches our request
        if let Some(req) = self.requests.get(peer_key) {
            if res.req == *req {
                // Check the signature
                if res.check(&self.public_key, peer_key) {
                    // Track the response
                    self.res_seq_ctr += 1;
                    self.res_seqs.insert(*peer_key, self.res_seq_ctr);
                    self.responses.insert(*peer_key, res.clone());

                    // Update latency for all connections to this peer
                    if let Some(peers) = self.peers.get_by_key(peer_key) {
                        let ports: Vec<_> = peers.keys().copied().collect();
                        for port in ports {
                            if let Some(info) = self.peers.get_mut(peer_key, port) {
                                info.update_latency(rtt);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handle a router announcement.
    pub fn handle_announce(&mut self, from_key: &PublicKey, ann: &RouterAnnounce) -> bool {
        if !ann.check() {
            return false;
        }

        // Check if we should accept this announcement
        if let Some(existing) = self.infos.get(&ann.key) {
            // Logic to determine if new announcement is better
            match existing.sig_res.req.seq.cmp(&ann.sig_res.req.seq) {
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    // Same seq, compare parent
                    if existing.parent.less(&ann.parent) {
                        return false;
                    }
                    if !ann.parent.less(&existing.parent) {
                        // Same parent, compare nonce
                        if ann.sig_res.req.nonce >= existing.sig_res.req.nonce {
                            return false;
                        }
                    }
                }
            }
        }

        // Accept the announcement
        let info = RouterInfo {
            parent: ann.parent,
            sig_res: ann.sig_res.clone(),
            sig: ann.sig,
        };

        // Clean up sent info
        for sent in self.sent.values_mut() {
            sent.remove(&ann.key);
        }
        self.path_cache.clear();

        // Store the info
        self.infos.insert(ann.key, info);

        // Mark that we received this from the sending peer
        if let Some(sent) = self.sent.get_mut(from_key) {
            sent.insert(ann.key);
        }

        true
    }

    /// Become the root of the tree.
    pub fn become_root(&mut self) -> bool {
        let req = self.new_sig_req();

        let mut res = RouterSigRes {
            req: req.clone(),
            port: 0,
            psig: Signature::default(),
        };

        // Self-sign
        let msg = res.bytes_for_sig(&self.public_key, &self.public_key);
        res.psig = self.private_key.sign(&msg);

        let ann = RouterAnnounce {
            key: self.public_key,
            parent: self.public_key,
            sig_res: res.clone(),
            sig: res.psig,
        };

        if !ann.check() {
            return false;
        }

        // Update our own info
        let info = RouterInfo {
            parent: self.public_key,
            sig_res: res,
            sig: ann.sig,
        };
        self.infos.insert(self.public_key, info);

        true
    }

    /// Get the ancestry path to the root for a key.
    pub fn get_ancestry(&self, key: &PublicKey) -> Vec<PublicKey> {
        let mut ancestry = Vec::new();
        let mut visited = HashSet::new();
        let mut current = *key;

        while !visited.contains(&current) {
            if let Some(info) = self.infos.get(&current) {
                visited.insert(current);
                ancestry.push(current);
                if current == info.parent {
                    break; // Reached root
                }
                current = info.parent;
            } else {
                break;
            }
        }

        ancestry.reverse(); // Root first
        ancestry
    }

    /// Get the root and path for a destination.
    pub fn get_root_and_path(&self, dest: &PublicKey) -> (PublicKey, Vec<PeerPort>) {
        let mut ports = Vec::new();
        let mut visited = HashSet::new();
        let mut root = *dest;
        let mut next = *dest;

        while !visited.contains(&next) {
            if let Some(info) = self.infos.get(&next) {
                root = next;
                visited.insert(next);
                if next == info.parent {
                    break;
                }
                ports.push(info.sig_res.port);
                next = info.parent;
            } else {
                break;
            }
        }

        ports.reverse();
        (root, ports)
    }

    /// Find a known public key that corresponds to the given Yggdrasil IPv6 address.
    ///
    /// This checks all known router infos and currently connected peers, returning
    /// the first key whose derived address matches the provided address.
    pub fn key_for_address(&self, addr: &Address) -> Option<PublicKey> {
        let mut seen = HashSet::new();

        // Known router infos (includes ourselves once rooted) and connected peers.
        let candidates = self
            .infos
            .keys()
            .copied()
            .chain(self.peers.iter().map(|(k, _)| *k))
            .chain(std::iter::once(self.public_key));

        for key in candidates {
            // Skip duplicates to avoid extra address computations.
            if !seen.insert(key) {
                continue;
            }

            if let Some(derived) = yggdrasil_address::addr_for_key(&key) {
                if &derived == addr {
                    return Some(key);
                }
            }
        }

        None
    }

    /// Calculate tree distance between paths.
    fn get_dist(&self, dest_path: &[PeerPort], key: &PublicKey) -> u64 {
        let key_path = self.path_cache.get(key).cloned().unwrap_or_else(|| {
            let (_, path) = self.get_root_and_path(key);
            path
        });

        let end = dest_path.len().min(key_path.len());
        let mut dist = (key_path.len() + dest_path.len()) as u64;

        for i in 0..end {
            if key_path[i] == dest_path[i] {
                dist -= 2;
            } else {
                break;
            }
        }

        dist
    }

    /// Lookup the next hop for a traffic packet.
    pub fn lookup(&self, path: &[PeerPort], watermark: &mut u64) -> Option<(PublicKey, PeerPort)> {
        let self_dist = self.get_dist(path, &self.public_key);

        if self_dist >= *watermark {
            return None;
        }
        *watermark = self_dist;

        let mut best: Option<(PublicKey, PeerPort, u64, u64)> = None;

        for (key, peers) in self.peers.iter() {
            let dist = self.get_dist(path, key);
            if dist >= self_dist {
                continue;
            }

            for (port, info) in peers {
                let cost = info.cost();
                let cpd = cost / (self_dist - dist); // Cost per distance

                let accept = || Some((*key, *port, cpd, dist));

                match &best {
                    None => best = accept(),
                    Some((bkey, bport, bcpd, bdist)) => {
                        if key == bkey
                            && info.priority
                                < self
                                    .peers
                                    .get_by_port(*bport)
                                    .map(|p| p.priority)
                                    .unwrap_or(u8::MAX)
                        {
                            best = accept();
                        } else if key == bkey {
                            continue;
                        } else if cpd < *bcpd {
                            best = accept();
                        } else if cpd > *bcpd {
                            continue;
                        } else if dist < *bdist {
                            best = accept();
                        } else if dist > *bdist {
                            continue;
                        } else if info.order
                            < self
                                .peers
                                .get_by_port(*bport)
                                .map(|p| p.order)
                                .unwrap_or(u64::MAX)
                        {
                            best = accept();
                        }
                    }
                }
            }
        }

        best.map(|(key, port, _, _)| (key, port))
    }

    /// Get a cloned path for the destination if known.
    pub fn get_path(&self, dest: &PublicKey) -> Option<Vec<PeerPort>> {
        if self.infos.contains_key(dest) {
            Some(self.get_root_and_path(dest).1)
        } else {
            None
        }
    }

    /// Retrieve a cached path discovered via the pathfinder (if any).
    pub fn get_pathfinder_path(&self, dest: &PublicKey) -> Option<Vec<PeerPort>> {
        self.pathfinder.get_path(dest).cloned()
    }

    /// Reset the path timeout for a destination when we see traffic from it.
    pub fn reset_path_timeout(&mut self, key: &PublicKey) {
        self.pathfinder.reset_timeout(key);
    }

    /// List all pending signature requests (for dispatch to peers).
    pub fn pending_requests(&self) -> Vec<(PublicKey, RouterSigReq)> {
        self.requests.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Collect router announcements that have not yet been sent to peers.
    /// Marks them as sent so repeated calls only emit new information.
    pub fn collect_announcements(&mut self) -> Vec<(PublicKey, RouterAnnounce)> {
        let mut out = Vec::new();

        for (peer, sent_set) in self.sent.iter_mut() {
            for (key, info) in self.infos.iter() {
                if peer == key {
                    // Don't send a node its own announcement
                    continue;
                }

                if sent_set.insert(*key) {
                    out.push((*peer, info.get_announce(*key)));
                }
            }
        }

        out
    }

    /// Perform maintenance tasks.
    pub fn do_maintenance(&mut self) {
        self.do_root2 = self.do_root2 || self.do_root1;
        self.path_cache.clear();
        self.update_ancestries();
        self.fix();

        // Clean up pathfinder
        self.pathfinder.cleanup_expired();
    }

    /// Update ancestry cache.
    fn update_ancestries(&mut self) {
        for key in self.peers.iter().map(|(k, _)| *k).collect::<Vec<_>>() {
            let ancestry = self.get_ancestry(&key);
            self.ancestries.insert(key, ancestry);
        }
    }

    /// Fix our routing state (select parent, become root if needed).
    fn fix(&mut self) {
        let mut best_root = self.public_key;
        let mut best_parent = self.public_key;
        let mut best_cost = u64::MAX;

        // Check current parent
        if let Some(self_info) = self.infos.get(&self.public_key) {
            if self.peers.is_connected(&self_info.parent) {
                let (root, _) = self.get_root_and_path(&self.public_key);
                if root.less(&best_root) {
                    // Calculate cost through current parent
                    if let Some(peers) = self.peers.get_by_key(&self_info.parent) {
                        for info in peers.values() {
                            let cost = info.cost();
                            if cost < best_cost {
                                best_root = root;
                                best_parent = self_info.parent;
                                best_cost = cost;
                            }
                        }
                    }
                }
            }
        }

        // Check if any peer offers a better root
        for (pk, _) in self.responses.iter() {
            if self.infos.get(pk).is_none() {
                continue;
            }

            let (peer_root, _) = self.get_root_and_path(pk);

            if let Some(peers) = self.peers.get_by_key(pk) {
                for info in peers.values() {
                    let cost = info.cost();

                    if peer_root.less(&best_root) || (peer_root == best_root && cost < best_cost) {
                        best_root = peer_root;
                        best_parent = *pk;
                        best_cost = cost;
                    }
                }
            }
        }

        // Decide what to do
        let current_parent = self
            .infos
            .get(&self.public_key)
            .map(|i| i.parent)
            .unwrap_or(self.public_key);

        if self.refresh || self.do_root1 || self.do_root2 || current_parent != best_parent {
            if best_root != self.public_key {
                // Try to use the response from best_parent
                if let Some(res) = self.responses.get(&best_parent).cloned() {
                    if self.use_response(&best_parent, &res) {
                        self.refresh = false;
                        self.do_root1 = false;
                        self.do_root2 = false;
                        self.send_requests();
                    }
                }
            } else if self.do_root2 {
                // Become root
                if self.become_root() {
                    self.refresh = false;
                    self.do_root1 = false;
                    self.do_root2 = false;
                    self.send_requests();
                }
            } else if !self.do_root1 {
                self.do_root1 = true;
            }
        }
    }

    /// Use a signature response to update our routing info.
    fn use_response(&mut self, peer_key: &PublicKey, res: &RouterSigRes) -> bool {
        let msg = res.bytes_for_sig(&self.public_key, peer_key);
        let sig = self.private_key.sign(&msg);

        let info = RouterInfo {
            parent: *peer_key,
            sig_res: res.clone(),
            sig,
        };

        let ann = info.get_announce(self.public_key);
        if !ann.check() {
            return false;
        }

        // Clear sent tracking and cache
        for sent in self.sent.values_mut() {
            sent.remove(&self.public_key);
        }
        self.path_cache.clear();

        self.infos.insert(self.public_key, info);
        true
    }

    /// Send signature requests to all peers.
    fn send_requests(&mut self) {
        self.requests.clear();
        self.responses.clear();
        self.res_seqs.clear();
        self.res_seq_ctr = 0;

        let req = self.new_sig_req();
        for key in self.peers.iter().map(|(k, _)| *k).collect::<Vec<_>>() {
            self.requests.insert(key, req.clone());
        }
    }
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("public_key", &self.public_key)
            .field("peer_count", &self.peers.peer_count())
            .field("info_count", &self.infos.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultCallbacks;

    #[test]
    fn test_router_creation() {
        let key = PrivateKey::generate();
        let config = RouterConfig::default();
        let callbacks = Arc::new(DefaultCallbacks);

        let router = Router::new(key, config, callbacks);
        assert_eq!(router.peers.peer_count(), 0);
    }

    #[test]
    fn test_become_root() {
        let key = PrivateKey::generate();
        let config = RouterConfig::default();
        let callbacks = Arc::new(DefaultCallbacks);

        let mut router = Router::new(key, config, callbacks);
        assert!(router.become_root());

        // Should have our own info now
        assert!(router.infos.contains_key(&router.public_key));
    }

    #[test]
    fn test_get_ancestry() {
        let key = PrivateKey::generate();
        let config = RouterConfig::default();
        let callbacks = Arc::new(DefaultCallbacks);

        let mut router = Router::new(key, config, callbacks);
        router.become_root();

        let ancestry = router.get_ancestry(&router.public_key);
        assert_eq!(ancestry.len(), 1);
        assert_eq!(ancestry[0], router.public_key);
    }

    #[test]
    fn test_nonce_generation_is_random() {
        let key = PrivateKey::generate();
        let config = RouterConfig::default();
        let callbacks = Arc::new(DefaultCallbacks);

        let router = Router::new(key, config, callbacks);

        // Generate multiple nonces and verify they are different
        let nonce1 = router.new_sig_req().nonce;
        let nonce2 = router.new_sig_req().nonce;
        let nonce3 = router.new_sig_req().nonce;

        // All nonces should be non-zero and different from each other
        assert_ne!(nonce1, 0, "Nonce should not be zero");
        assert_ne!(nonce2, 0, "Nonce should not be zero");
        assert_ne!(nonce3, 0, "Nonce should not be zero");
        assert_ne!(nonce1, nonce2, "Nonces should be different");
        assert_ne!(nonce2, nonce3, "Nonces should be different");
        assert_ne!(nonce1, nonce3, "Nonces should be different");
    }
}
