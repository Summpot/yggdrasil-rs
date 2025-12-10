use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hex;
use parking_lot::RwLock;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, trace, warn};
use yggdrasil_link::OutgoingPacket;
use yggdrasil_routing::{Router, RouterCallbacks, RouterConfig};
use yggdrasil_session::{HandleResult, WriteResult};
use yggdrasil_types::{PeerPort, PublicKey, WireError};
use yggdrasil_wire::{
    PathBroken, PathLookup, PathNotify, PathNotifyInfo, Traffic, WireEncode, WirePacketType,
};

use crate::debug_logger::PlaintextDebugLogger;
use crate::Core;

/// Registry for tracking peer outgoing channels.
pub type PeerRegistry = Arc<DashMap<PublicKey, mpsc::Sender<OutgoingPacket>>>;

#[derive(Default)]
struct RouterActions {
    sig_requests: Vec<(PublicKey, yggdrasil_wire::RouterSigReq)>,
    announcements: Vec<(PublicKey, yggdrasil_wire::RouterAnnounce)>,
}

/// Router callbacks used by the main crate to configure bloom transforms.
struct RoutingCallbacks;

impl RouterCallbacks for RoutingCallbacks {
    fn bloom_transform(&self, key: &PublicKey) -> PublicKey {
        // Match the Go implementation by using the /64 subnet-derived key so
        // that lookups can operate on partial keys reconstructed from
        // addresses.
        yggdrasil_address::subnet_for_key(key)
            .map(|s| s.get_key())
            .unwrap_or(*key)
    }

    fn path_notify(&self, _key: &PublicKey) {}
}

/// Routing runtime that drives the router state machine and packet forwarding.
pub struct RoutingRuntime {
    core: Arc<Core>,
    router: RwLock<Router>,
    last_sig_requests: RwLock<HashMap<PublicKey, (u64, u64)>>,
    peer_ports: RwLock<HashMap<PublicKey, PeerPort>>, // track latest port per peer
    debug_logger: Option<Arc<PlaintextDebugLogger>>,
}

impl RoutingRuntime {
    pub fn new(core: Arc<Core>, debug_logger: Option<Arc<PlaintextDebugLogger>>) -> Self {
        let callbacks = Arc::new(RoutingCallbacks);
        let mut router = Router::new(
            core.private_key().clone(),
            RouterConfig::default(),
            callbacks,
        );
        // Start as root so we always have our own routing info
        let _ = router.become_root();

        Self {
            core,
            router: RwLock::new(router),
            last_sig_requests: RwLock::new(HashMap::new()),
            peer_ports: RwLock::new(HashMap::new()),
            debug_logger,
        }
    }

    /// Register a new peer with the routing subsystem and dispatch initial control traffic.
    pub fn register_peer(
        &self,
        key: PublicKey,
        port: PeerPort,
        priority: u8,
        registry: &PeerRegistry,
    ) {
        {
            let mut ports = self.peer_ports.write();
            ports.insert(key, port);
        }

        let actions = {
            let mut router = self.router.write();
            router.add_peer_with_port(key, port, priority);
            router.do_maintenance();
            self.collect_actions_locked(&mut router)
        };

        self.dispatch(actions, registry);
    }

    /// Handle a peer disconnection.
    pub fn peer_disconnected(&self, key: &PublicKey, registry: &PeerRegistry) {
        let port_opt = { self.peer_ports.write().remove(key) };
        if let Some(port) = port_opt {
            let actions = {
                let mut router = self.router.write();
                router.remove_peer(key, port);
                router.do_maintenance();
                self.collect_actions_locked(&mut router)
            };
            self.dispatch(actions, registry);
        }
    }

    /// Handle a signature response from a peer.
    pub fn handle_sig_response(
        &self,
        from: PublicKey,
        res: yggdrasil_wire::RouterSigRes,
        rtt: Duration,
        registry: &PeerRegistry,
    ) {
        let actions = {
            let mut router = self.router.write();
            router.handle_sig_response(&from, &res, rtt);
            router.do_maintenance();
            self.collect_actions_locked(&mut router)
        };
        self.dispatch(actions, registry);
    }

    /// Handle an incoming router announcement.
    pub fn handle_announce(
        &self,
        from: PublicKey,
        ann: yggdrasil_wire::RouterAnnounce,
        registry: &PeerRegistry,
    ) {
        let actions = {
            let mut router = self.router.write();
            let changed = router.handle_announce(&from, &ann);
            if changed {
                router.do_maintenance();
            }
            self.collect_actions_locked(&mut router)
        };
        self.dispatch(actions, registry);
    }

    /// Periodic router maintenance tick.
    pub fn maintenance_tick(&self, registry: &PeerRegistry) {
        let actions = {
            let mut router = self.router.write();
            router.do_maintenance();
            self.collect_actions_locked(&mut router)
        };
        self.dispatch(actions, registry);
    }

    /// Handle IPv6 packet read from TUN.
    pub fn handle_outgoing_ipv6_packet(&self, packet: &[u8], registry: &PeerRegistry) {
        let dst_bytes: [u8; 16] = packet[24..40]
            .try_into()
            .expect("IPv6 destination address slice is exactly 16 bytes");
        let dest_addr: std::net::Ipv6Addr = dst_bytes.into();

        // Only handle Yggdrasil range
        if dst_bytes[0] != 0x02 && dst_bytes[0] != 0x03 {
            trace!(dst = %dest_addr, "Destination not in Yggdrasil range, ignoring");
            return;
        }

        let dest_ygg_addr = yggdrasil_address::Address::from_bytes(dst_bytes);
        let dest_key = {
            let router = self.router.read();
            router.key_for_address(&dest_ygg_addr)
        };

        let dest_key = match dest_key {
            Some(key) => key,
            None => {
                // Attempt a key lookup using the partial key derived from the
                // destination address. This mirrors the Go implementation's
                // SendLookup path when we don't yet know the full public key.
                let partial = dest_ygg_addr.get_key();
                warn!(dst = %dest_addr, "No known public key for destination address, initiating lookup");
                self.initiate_path_lookup(partial, None, registry);
                return;
            }
        };

        if let Some(logger) = &self.debug_logger {
            logger.log_out(&dest_key, packet);
        }

        let sessions = self.core.sessions();
        match sessions.write_to(dest_key, packet.to_vec()) {
            WriteResult::Send { data } => self.send_encrypted_payload(dest_key, data, registry),
            WriteResult::NeedInit { dest: _, init } => {
                match sessions.encrypt_init(&dest_key, &init) {
                    Ok(init_data) => self.send_encrypted_payload(dest_key, init_data, registry),
                    Err(e) => warn!(
                        dest = %hex::encode(&dest_key.as_bytes()[..8]),
                        error = %e,
                        "Failed to encrypt session init"
                    ),
                }
            }
        }
    }

    /// Handle a Traffic packet received from a peer.
    pub fn handle_incoming_traffic(
        &self,
        from: PublicKey,
        traffic: Traffic,
        registry: &PeerRegistry,
        incoming_tx: &mpsc::UnboundedSender<Vec<u8>>,
    ) {
        debug!(
            from = %hex::encode(&from.as_bytes()[..8]),
            source = %hex::encode(&traffic.source.as_bytes()[..8]),
            dest = %hex::encode(&traffic.dest.as_bytes()[..8]),
            our_key = %hex::encode(&self.core.public_key().as_bytes()[..8]),
            payload_len = traffic.payload.len(),
            is_for_us = (traffic.dest == *self.core.public_key()),
            "Processing incoming traffic packet"
        );

        if traffic.dest == *self.core.public_key() {
            {
                let mut router = self.router.write();
                router.reset_path_timeout(&from);
            }

            let sessions = self.core.sessions();
            match sessions.handle_data(&from, &traffic.payload) {
                HandleResult::Received { payload } => {
                    if let Some(logger) = &self.debug_logger {
                        logger.log_in(&from, &payload);
                    }

                    debug!(
                        from = %hex::encode(&from.as_bytes()[..8]),
                        payload_len = payload.len(),
                        "Session decrypted payload, sending to TUN"
                    );
                    if let Err(e) = incoming_tx.send(payload) {
                        debug!(error = %e, "Failed to deliver decrypted packet to TUN channel");
                    } else {
                        trace!("Decrypted payload successfully sent to TUN channel");
                    }
                }
                HandleResult::SendInit { dest, init } => {
                    match sessions.encrypt_init(&dest, &init) {
                        Ok(init_data) => self.send_encrypted_payload(dest, init_data, registry),
                        Err(e) => debug!(
                            dest = %hex::encode(&dest.as_bytes()[..8]),
                            error = %e,
                            "Failed to encrypt session init"
                        ),
                    }
                }
                HandleResult::SendAck {
                    dest,
                    ack,
                    buffered_data,
                } => {
                    match sessions.encrypt_ack(&dest, &ack) {
                        Ok(ack_data) => self.send_encrypted_payload(dest, ack_data, registry),
                        Err(e) => debug!(
                            dest = %hex::encode(&dest.as_bytes()[..8]),
                            error = %e,
                            "Failed to encrypt session ack"
                        ),
                    }
                    if let Some(buf) = buffered_data {
                        if let Err(e) = incoming_tx.send(buf) {
                            debug!(error = %e, "Failed to deliver buffered packet to TUN channel");
                        }
                    }
                }
                HandleResult::SendBuffered { dest, data } => {
                    debug!(
                        from = %hex::encode(&from.as_bytes()[..8]),
                        dest = %hex::encode(&dest.as_bytes()[..8]),
                        "Session buffered data, sending back"
                    );
                    self.send_encrypted_payload(dest, data, registry);
                }
                HandleResult::Ignored => {
                    debug!(
                        from = %hex::encode(&from.as_bytes()[..8]),
                        "Ignored traffic packet (possibly dummy or out of sequence)"
                    );
                }
                HandleResult::Error => {
                    debug!(from = %hex::encode(&from.as_bytes()[..8]), "Error handling traffic packet");
                }
            }
            return;
        }

        // Forward traffic towards destination
        self.forward_traffic(traffic, registry);
    }

    /// Handle a PathLookup packet.
    pub fn handle_path_lookup(&self, from: PublicKey, lookup: PathLookup, registry: &PeerRegistry) {
        let (self_xform, dest_xform, self_path) = {
            let router = self.router.read();
            (
                router.transform_key(self.core.public_key()),
                router.transform_key(&lookup.dest),
                router.get_path(&self.core.public_key()),
            )
        };

        if dest_xform == self_xform {
            // Respond with PathNotify containing our coordinates
            if let Some(self_path) = self_path {
                let mut info = PathNotifyInfo {
                    seq: current_epoch_seconds(),
                    path: self_path.clone(),
                    sig: Default::default(),
                };
                info.sign(self.core.private_key());

                let notify = PathNotify {
                    path: lookup.from.clone(),
                    watermark: u64::MAX,
                    source: *self.core.public_key(),
                    dest: lookup.source,
                    info,
                };
                self.forward_path_notify(notify, registry);
            }
            return;
        }

        let mut forwarded = false;

        // Forward lookup using routing path to destination if we already know it
        if let Some(dest_path) = self.get_path_for(&lookup.dest) {
            let next_lookup = lookup.clone();
            // Ensure watermark semantics by reusing Traffic-like lookup
            let mut watermark = u64::MAX;
            if let Some(next) = self.next_hop_for_path(&dest_path, &mut watermark) {
                self.send_control_packet(
                    next,
                    next_lookup,
                    WirePacketType::ProtoPathLookup,
                    registry,
                    true,
                );
                forwarded = true;
            } else {
                debug!(
                    dest = %hex::encode(&lookup.dest.as_bytes()[..8]),
                    "No route to forward path lookup"
                );
            }
        }

        if forwarded {
            return;
        }

        // If we don't know the path, multicast the lookup outward while
        // respecting throttling to avoid floods.
        let should_forward = {
            let router = self.router.read();
            router.should_send_lookup_for(&lookup.dest, &dest_xform)
        };

        if !should_forward {
            trace!(
                dest = %hex::encode(&lookup.dest.as_bytes()[..8]),
                "Dropping throttled path lookup"
            );
            return;
        }

        {
            let mut router = self.router.write();
            router.mark_lookup_sent_for(lookup.dest, dest_xform);
        }

        self.broadcast_lookup(lookup, registry, Some(from));
    }

    /// Forward a PathNotify packet.
    pub fn forward_path_notify(&self, mut notify: PathNotify, registry: &PeerRegistry) {
        let mut watermark = notify.watermark;
        if let Some(next) = self.next_hop_for_path(&notify.path, &mut watermark) {
            notify.watermark = watermark;
            self.send_control_packet(
                next,
                notify,
                WirePacketType::ProtoPathNotify,
                registry,
                true,
            );
            return;
        }

        if notify.dest != *self.core.public_key() {
            debug!(
                dest = %hex::encode(&notify.dest.as_bytes()[..8]),
                "No route for path notify"
            );
            return;
        }

        // Consume the notify for ourselves and forward any cached traffic now
        // that we have a usable path.
        let cached = {
            let mut router = self.router.write();
            router.handle_path_notify(&notify)
        };

        if let Some(mut traffic) = cached.map(|b| *b) {
            if traffic.path.is_empty() {
                traffic.path = notify.info.path.clone();
            }

            let self_path = self
                .get_path_for(&self.core.public_key())
                .unwrap_or_default();
            traffic.from = self_path;
            traffic.watermark = u64::MAX;

            self.forward_traffic(traffic, registry);
        }
    }

    /// Forward a PathBroken packet.
    pub fn forward_path_broken(&self, mut broken: PathBroken, registry: &PeerRegistry) {
        let mut watermark = broken.watermark;
        if let Some(next) = self.next_hop_for_path(&broken.path, &mut watermark) {
            broken.watermark = watermark;
            self.send_control_packet(
                next,
                broken,
                WirePacketType::ProtoPathBroken,
                registry,
                true,
            );
            return;
        }

        if broken.source != *self.core.public_key() {
            debug!(
                dest = %hex::encode(&broken.dest.as_bytes()[..8]),
                "No route for path broken"
            );
            return;
        }

        {
            let mut router = self.router.write();
            router.mark_path_broken(&broken.dest);
        }

        self.initiate_path_lookup(broken.dest, None, registry);
    }

    /// Send encrypted payload towards destination, performing routing lookup.
    fn send_encrypted_payload(&self, dest: PublicKey, data: Vec<u8>, registry: &PeerRegistry) {
        if let Some(traffic) = self.build_traffic(dest, data.clone()) {
            self.forward_traffic(traffic, registry);
            return;
        }

        // If we couldn't build a routed packet, start a lookup and cache the
        // traffic while we search for a path. This mirrors the Go pathfinder
        // behaviour.
        let traffic = Traffic::new(*self.core.public_key(), dest, data);
        self.initiate_path_lookup(dest, Some(traffic.clone()), registry);

        if let Some(tx) = registry.get(&dest) {
            // Fallback: direct send to known peer even if path missing
            self.send_traffic_to_peer(dest, traffic, &tx);
        } else {
            debug!(dest = %hex::encode(&dest.as_bytes()[..8]), "No route to destination");
        }
    }

    /// Build a traffic packet with routing metadata if the destination is known.
    fn build_traffic(&self, dest: PublicKey, data: Vec<u8>) -> Option<Traffic> {
        let router = self.router.read();
        let dest_path = router
            .get_path(&dest)
            .or_else(|| router.get_pathfinder_path(&dest))?;
        let self_path = router.get_path(&self.core.public_key()).unwrap_or_default();

        let mut traffic = Traffic::new(*self.core.public_key(), dest, data);
        traffic.path = dest_path;
        traffic.from = self_path;
        traffic.watermark = u64::MAX;
        Some(traffic)
    }

    fn forward_traffic(&self, mut traffic: Traffic, registry: &PeerRegistry) {
        let mut watermark = traffic.watermark;
        if let Some(next) = self.next_hop_for_path(&traffic.path, &mut watermark) {
            traffic.watermark = watermark;
            
            debug!(
                peer = %hex::encode(&next.as_bytes()[..8]),
                dest = %hex::encode(&traffic.dest.as_bytes()[..8]),
                registry_size = registry.len(),
                "Looking up next hop in peer registry"
            );
            
            if let Some(tx) = registry.get(&next) {
                let peer_hex = hex::encode(&next.as_bytes()[..8]);
                let dest_hex = hex::encode(&traffic.dest.as_bytes()[..8]);

                if let Some(addr) = yggdrasil_address::addr_for_key(&next) {
                    debug!(peer = %peer_hex, peer_addr = %addr, dest = %dest_hex, "Forwarding traffic to next hop");
                } else {
                    debug!(peer = %peer_hex, dest = %dest_hex, "Forwarding traffic to next hop");
                }
                self.send_traffic_to_peer(next, traffic, tx.value());
            } else {
                debug!(
                    peer = %hex::encode(&next.as_bytes()[..8]),
                    registry_keys = ?registry.iter().map(|e| hex::encode(&e.key().as_bytes()[..8])).collect::<Vec<_>>(),
                    "No channel for next hop in registry"
                );
            }
        } else {
            debug!(
                dest = %hex::encode(&traffic.dest.as_bytes()[..8]),
                "Dropping traffic with no route"
            );
        }
    }

    fn send_traffic_to_peer(
        &self,
        peer: PublicKey,
        traffic: Traffic,
        tx: &mpsc::Sender<OutgoingPacket>,
    ) {
        let mut payload = Vec::new();
        if let Err(e) = traffic.wire_encode(&mut payload) {
            debug!(peer = %hex::encode(&peer.as_bytes()[..8]), error = %e, "Failed to encode traffic packet");
            return;
        }

        let packet = OutgoingPacket {
            packet_type: WirePacketType::Traffic,
            payload: payload.clone(),
        };

        debug!(
            peer = %hex::encode(&peer.as_bytes()[..8]),
            dest = %hex::encode(&traffic.dest.as_bytes()[..8]),
            payload_len = payload.len(),
            "Sending traffic packet to peer channel"
        );

        self.send_with_backpressure(tx, packet, true, &peer);
    }

    fn send_with_backpressure(
        &self,
        tx: &mpsc::Sender<OutgoingPacket>,
        packet: OutgoingPacket,
        allow_drop: bool,
        peer: &PublicKey,
    ) {
        let packet_type = packet.packet_type;
        match tx.try_send(packet) {
            Ok(_) => {}
            Err(TrySendError::Full(packet)) => {
                if allow_drop {
                    debug!(peer = %hex::encode(&peer.as_bytes()[..8]), packet_type = ?packet_type, "Dropping packet due to backpressure");
                } else if let Err(e) = tx.blocking_send(packet) {
                    debug!(peer = %hex::encode(&peer.as_bytes()[..8]), packet_type = ?packet_type, error = %e, "Failed to deliver packet under backpressure");
                }
            }
            Err(TrySendError::Closed(_)) => {
                debug!(peer = %hex::encode(&peer.as_bytes()[..8]), packet_type = ?packet_type, "Peer channel closed while sending");
            }
        }
    }

    fn next_hop_for_path(&self, path: &[PeerPort], watermark: &mut u64) -> Option<PublicKey> {
        let router = self.router.read();
        router.lookup(path, watermark).map(|(peer, _port)| peer)
    }

    fn collect_actions_locked(&self, router: &mut Router) -> RouterActions {
        let requests = self.filter_sig_requests(router.pending_requests());
        let announcements = router.collect_announcements();
        RouterActions {
            sig_requests: requests,
            announcements,
        }
    }

    fn filter_sig_requests(
        &self,
        requests: Vec<(PublicKey, yggdrasil_wire::RouterSigReq)>,
    ) -> Vec<(PublicKey, yggdrasil_wire::RouterSigReq)> {
        let mut last = self.last_sig_requests.write();
        requests
            .into_iter()
            .filter(|(peer, req)| match last.get(peer) {
                Some((seq, nonce)) if *seq == req.seq && *nonce == req.nonce => false,
                _ => {
                    last.insert(*peer, (req.seq, req.nonce));
                    true
                }
            })
            .collect()
    }

    fn dispatch(&self, actions: RouterActions, registry: &PeerRegistry) {
        for (peer, req) in actions.sig_requests {
            self.send_control(
                peer,
                WirePacketType::ProtoSigReq,
                |buf| req.wire_encode(buf),
                registry,
                false,
            );
        }

        for (peer, ann) in actions.announcements {
            self.send_control(
                peer,
                WirePacketType::ProtoAnnounce,
                |buf| ann.wire_encode(buf),
                registry,
                false,
            );
        }
    }

    fn send_control<F>(
        &self,
        peer: PublicKey,
        kind: WirePacketType,
        encode: F,
        registry: &PeerRegistry,
        allow_drop: bool,
    ) where
        F: FnOnce(&mut Vec<u8>) -> Result<(), WireError>,
    {
        if let Some(tx) = registry.get(&peer) {
            let mut payload = Vec::new();
            if let Err(e) = encode(&mut payload) {
                debug!(peer = %hex::encode(&peer.as_bytes()[..8]), error = %e, "Failed to encode control packet");
                return;
            }

            let packet = OutgoingPacket {
                packet_type: kind,
                payload,
            };

            self.send_with_backpressure(tx.value(), packet, allow_drop, &peer);
        } else {
            trace!(peer = %hex::encode(&peer.as_bytes()[..8]), "No peer channel for control packet");
        }
    }

    fn send_control_packet<P>(
        &self,
        peer: PublicKey,
        packet: P,
        kind: WirePacketType,
        registry: &PeerRegistry,
        allow_drop: bool,
    ) where
        P: WireEncode,
    {
        self.send_control(peer, kind, |buf| packet.wire_encode(buf), registry, allow_drop);
    }

    /// Broadcast a PathLookup to all known peers except an optional excluded peer.
    fn broadcast_lookup(
        &self,
        lookup: PathLookup,
        registry: &PeerRegistry,
        exclude: Option<PublicKey>,
    ) {
        for entry in registry.iter() {
            let peer = *entry.key();
            if let Some(skip) = exclude {
                if skip == peer {
                    continue;
                }
            }

            let tx = entry.value();
            let mut payload = Vec::new();
            if let Err(e) = lookup.wire_encode(&mut payload) {
                debug!(peer = %hex::encode(&peer.as_bytes()[..8]), error = %e, "Failed to encode path lookup");
                continue;
            }

            let packet = OutgoingPacket {
                packet_type: WirePacketType::ProtoPathLookup,
                payload,
            };

            self.send_with_backpressure(tx, packet, true, &peer);
        }
    }

    /// Initiate a lookup for the given destination key (which may be partial/transformed).
    fn initiate_path_lookup(
        &self,
        dest: PublicKey,
        maybe_traffic: Option<Traffic>,
        registry: &PeerRegistry,
    ) {
        let lookup = {
            let mut router = self.router.write();
            let xform = router.transform_key(&dest);

            if !router.should_send_lookup_for(&dest, &xform) {
                return;
            }

            let from_path = router.get_path(&self.core.public_key()).unwrap_or_default();

            router.mark_lookup_sent_for(dest, xform);

            if let Some(tr) = maybe_traffic {
                router.cache_rumor_traffic(xform, tr);
            }

            PathLookup {
                source: *self.core.public_key(),
                dest,
                from: from_path,
            }
        };

        self.broadcast_lookup(lookup, registry, None);
    }

    fn get_path_for(&self, key: &PublicKey) -> Option<Vec<PeerPort>> {
        let router = self.router.read();
        router.get_path(key)
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
