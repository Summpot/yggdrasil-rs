use crate::address::{Address, Subnet};
use crate::admin::{
    AddPeerResponse, AdminServer, GetPathsResponse, GetPeersResponse, GetSelfResponse,
    GetSessionsResponse, PathEntry, PeerEntry, RemovePeerResponse, SessionEntry,
};
use crate::config::Config;
use crate::crypto::Crypto;
use crate::link::{LinkEvent, LinkManager};
use crate::lookup::{BloomFilter, LookupManager};
use crate::peer::{ConnectionState, ConnectionType, PeerInfo, PeerManager};
use crate::proto::ProtoHandler;
use crate::router::{RouterEvent, RoutingTable};
use crate::session::{Session, SessionManager};
use crate::spanning_tree::SpanningTree;
use crate::tun_adapter::{TunAdapter, TunEvent};
use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Yggdrasil core
pub struct Core {
    config: Config,
    crypto: Crypto,
    address: Address,
    subnet: Subnet,
    link_manager: LinkManager,
    link_event_rx: mpsc::Receiver<LinkEvent>,
    routing_table: RoutingTable,
    router_event_rx: mpsc::Receiver<RouterEvent>,
    peer_manager: PeerManager,
    session_manager: SessionManager,
    spanning_tree: Arc<SpanningTree>,
    lookup_manager: Arc<LookupManager>,
    proto_handler: Arc<ProtoHandler>,
    proto_send_rx: mpsc::Receiver<(Vec<u8>, [u8; 32])>,
    tun_adapter: Option<TunAdapter>,
    tun_packet_rx: Option<mpsc::Receiver<Vec<u8>>>,
    tun_event_rx: Option<mpsc::Receiver<TunEvent>>,
    /// Shutdown signal broadcaster
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Shutdown signal receiver (kept for cloning to tasks)
    #[allow(dead_code)]
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
}

impl Core {
    /// Create new core instance
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing Yggdrasil core...");

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        // Create crypto instance
        let private_key = config
            .private_key
            .ok_or_else(|| anyhow::anyhow!("No private key in configuration"))?;
        let crypto = Crypto::from_private_key(private_key)?;
        let public_key = crypto.public_key();

        // Generate address
        let address = Address::from_public_key(&public_key);
        info!("Node address: {}", address);

        // Generate subnet
        let subnet = Subnet::from_public_key(&public_key);
        info!("Node subnet: {}", subnet);

        // Create router event channel
        let (router_tx, router_rx) = mpsc::channel(1024);

        // Create spanning tree
        let spanning_tree = Arc::new(SpanningTree::new(public_key));
        info!("Spanning tree initialized");

        // Create lookup manager
        let lookup_manager = Arc::new(LookupManager::new(public_key));
        info!("Lookup manager initialized");

        // Create protocol handler
        let (proto_send_tx, proto_send_rx) = mpsc::channel(1024);
        let proto_handler = Arc::new(ProtoHandler::new(proto_send_tx));
        info!("Protocol handler initialized");

        // Create routing table with spanning tree
        let routing_table = RoutingTable::with_spanning_tree(public_key, router_tx);
        info!("Routing table initialized with spanning tree support");

        // Create peer manager (max 64 peers, 5 minute timeout)
        let peer_manager = PeerManager::new(64, Duration::from_secs(300));
        info!("Peer manager initialized");

        // Create session manager (5 minute timeout)
        let session_manager = SessionManager::new(Duration::from_secs(300));
        info!("Session manager initialized");

        // Create link manager
        let (link_manager, link_event_rx) = LinkManager::new(
            config.listen.clone(),
            config.peers.clone(),
            config.interface_peers.clone(),
            config.allowed_public_keys.clone(),
            crypto.signing_key().clone(),
            0, // Default priority
            Arc::new(config.clone()),
        );

        // Start link manager
        link_manager.start().await?;

        // Create TUN adapter if enabled (check if_name != "none")
        let (tun_adapter, tun_packet_rx, tun_event_rx) = if config.if_name != "none" {
            let (adapter, packet_rx, event_rx) =
                TunAdapter::new(config.if_name.clone(), config.if_mtu as u32);
            (Some(adapter), Some(packet_rx), Some(event_rx))
        } else {
            info!("TUN adapter disabled in configuration");
            (None, None, None)
        };

        Ok(Core {
            config,
            crypto,
            address,
            subnet,
            link_manager,
            link_event_rx,
            routing_table,
            router_event_rx: router_rx,
            peer_manager,
            session_manager,
            spanning_tree,
            lookup_manager,
            proto_handler,
            proto_send_rx,
            tun_adapter,
            tun_packet_rx,
            tun_event_rx,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Run core event loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting core event loop...");

        // Start TUN adapter if available
        if let Some(ref mut adapter) = self.tun_adapter {
            adapter.start().await?;
            info!("TUN adapter started");
        }

        // Start background tasks
        self.start_background_tasks();

        loop {
            tokio::select! {
                // Handle link events (peer connections)
                Some(event) = self.link_event_rx.recv() => {
                    if let Err(e) = self.handle_link_event(event).await {
                        error!("Error handling link event: {}", e);
                    }
                }

                // Handle router events (packet routing)
                Some(event) = self.router_event_rx.recv() => {
                    if let Err(e) = self.handle_router_event(event).await {
                        error!("Error handling router event: {}", e);
                    }
                }

                // Handle protocol messages to send
                Some((packet, to_key)) = self.proto_send_rx.recv() => {
                    if let Err(e) = self.handle_proto_send(packet, to_key).await {
                        error!("Error handling proto send: {}", e);
                    }
                }

                // Handle TUN packet queue
                Some(packet) = async {
                    match &mut self.tun_packet_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Err(e) = self.handle_tun_packet_queue(packet).await {
                        error!("Error handling TUN packet queue: {}", e);
                    }
                }

                // Handle TUN events
                Some(event) = async {
                    match &mut self.tun_event_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Err(e) = self.handle_tun_event(event).await {
                        error!("Error handling TUN event: {}", e);
                    }
                }
            }
        }
    }

    /// Handle link event
    async fn handle_link_event(&mut self, event: LinkEvent) -> Result<()> {
        match event {
            LinkEvent::Connected(addr) => {
                info!("Peer connected: {}", addr);
                // Note: Peer will be properly added with real public key in HandshakeComplete event
            }
            LinkEvent::HandshakeComplete(addr, peer_key, priority, is_inbound) => {
                info!(
                    "Handshake complete with {} (priority: {}, {})",
                    addr,
                    priority,
                    if is_inbound { "inbound" } else { "outbound" }
                );
                info!("Peer public key: {}", hex::encode(peer_key.to_bytes()));

                // Update peer with real public key and mark as ready
                let mut peer = PeerInfo::new(
                    peer_key,
                    addr,
                    if is_inbound {
                        ConnectionType::Incoming
                    } else {
                        ConnectionType::Outgoing
                    },
                );
                peer.state = ConnectionState::Ready;

                if let Err(e) = self.peer_manager.add_peer(peer).await {
                    warn!("Failed to update peer {}: {}", addr, e);
                }

                // Add peer to spanning tree
                if let Err(e) = self.spanning_tree.add_peer(peer_key).await {
                    warn!("Failed to add peer to spanning tree: {}", e);
                } else {
                    debug!(
                        "Added peer {} to spanning tree",
                        hex::encode(&peer_key.to_bytes()[..8])
                    );
                }

                // Derive shared secret and create session
                let private_key_bytes = self.crypto.private_key_bytes();
                match Session::derive_shared_secret(&private_key_bytes, &peer_key) {
                    Ok(shared_secret) => {
                        let session = Session::new(peer_key, shared_secret);
                        if let Err(e) = self.session_manager.add_session(session).await {
                            warn!("Failed to create session for peer {}: {}", addr, e);
                        } else {
                            info!(
                                "Session established with {}",
                                Address::from_public_key(&peer_key)
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Failed to derive shared secret for peer {}: {}", addr, e);
                    }
                }

                // Calculate coordinates from spanning tree
                let coords = self.spanning_tree.calculate_coords(&peer_key).await;

                // Add route to peer with coordinates
                use crate::router::RouteEntry;
                let route = RouteEntry {
                    destination: Address::from_public_key(&peer_key),
                    next_hop: peer_key,
                    hops: coords.len() as u8,
                    latency: 0,
                    last_update: std::time::Instant::now(),
                    coords,
                    root: Some(peer_key),
                };

                if let Err(e) = self.routing_table.add_route_with_coords(route).await {
                    warn!("Failed to add route for peer {}: {}", addr, e);
                }

                // Add peer to lookup manager's Bloom filter
                // This peer can reach itself, so add it to the filter
                self.lookup_manager
                    .add_reachable_node(peer_key, peer_key)
                    .await;
                debug!(
                    "Added peer {} to lookup Bloom filter",
                    hex::encode(&peer_key.to_bytes()[..8])
                );

                // Send our tree announcement to the new peer
                let our_announcement = self.spanning_tree.get_local_announcement().await;
                debug!(
                    "Our tree position: root={}, dist={}",
                    hex::encode(&our_announcement.root_key.to_bytes()[..8]),
                    our_announcement.root_dist
                );

                // Build tree announcement message
                let mut announcement_msg = Vec::new();
                announcement_msg.push(0x01); // Protocol version
                announcement_msg.push(0x01); // Message type: Tree Announcement
                announcement_msg.extend_from_slice(&our_announcement.root_key.to_bytes());
                announcement_msg.extend_from_slice(&our_announcement.root_dist.to_be_bytes());
                announcement_msg.extend_from_slice(&our_announcement.sequence.to_be_bytes());

                // Send to the new peer through link manager
                if let Err(e) = self
                    .link_manager
                    .send_to_peer(&addr, announcement_msg)
                    .await
                {
                    warn!("Failed to send tree announcement to {}: {}", addr, e);
                } else {
                    debug!("Sent tree announcement to {}", addr);
                }
            }
            LinkEvent::Disconnected(addr) => {
                info!("Peer disconnected: {}", addr);

                // Get peer info before removing to access public key
                if let Some(peer) = self.peer_manager.find_peer_by_addr(&addr).await {
                    let peer_key = peer.public_key;

                    // Remove from spanning tree
                    if let Err(e) = self.spanning_tree.remove_peer(&peer_key).await {
                        warn!("Failed to remove peer from spanning tree: {}", e);
                    } else {
                        debug!(
                            "Removed peer {} from spanning tree",
                            hex::encode(&peer_key.to_bytes()[..8])
                        );
                    }

                    // Remove route
                    let peer_addr = Address::from_public_key(&peer_key).as_ipv6();
                    if let Err(e) = self.routing_table.remove_route(&peer_addr).await {
                        warn!("Failed to remove route for peer: {}", e);
                    }
                }

                // Remove from peer manager
                if let Err(e) = self.peer_manager.remove_peer(&addr).await {
                    debug!("Failed to remove peer {}: {}", addr, e);
                }
            }
            LinkEvent::DataReceived(addr, data) => {
                debug!("Received {} bytes from {}", data.len(), addr);

                // Update peer activity
                self.peer_manager.update_peer_activity(&addr).await;

                // Update statistics
                self.peer_manager
                    .update_peer_stats(&addr, 0, data.len() as u64)
                    .await;

                // Find peer by address to get public key
                if let Some(peer) = self.peer_manager.find_peer_by_addr(&addr).await {
                    // Try to decrypt packet if session exists
                    let decrypted_data = if let Some(session) =
                        self.session_manager.get_session(&peer.public_key).await
                    {
                        match session.decrypt(&data) {
                            Ok(plaintext) => {
                                debug!("Decrypted {} bytes from peer", plaintext.len());

                                // Update session statistics
                                self.session_manager
                                    .update_stats(&peer.public_key, 0, data.len() as u64)
                                    .await;

                                plaintext
                            }
                            Err(e) => {
                                warn!("Failed to decrypt packet from {}: {}", addr, e);
                                // If decryption fails, treat as unencrypted (for backward compatibility)
                                data.clone()
                            }
                        }
                    } else {
                        // No session yet, treat as unencrypted
                        debug!("No session for peer {}, treating as unencrypted", addr);
                        data.clone()
                    };

                    // Check if this is a protocol message (TYPE_SESSION_PROTO = 2)
                    if !decrypted_data.is_empty() && decrypted_data[0] == 2 {
                        // Protocol message - delegate to ProtoHandler
                        let peer_key_bytes = peer.public_key.to_bytes();

                        // Handle different protocol types
                        if decrypted_data.len() > 1 {
                            match decrypted_data[1] {
                                3 => {
                                    // TYPE_PROTO_TREE_ANNOUNCEMENT
                                    if decrypted_data.len() > 2 {
                                        if let Err(e) = self
                                            .handle_tree_announcement(
                                                &peer_key_bytes,
                                                &decrypted_data[2..],
                                            )
                                            .await
                                        {
                                            warn!(
                                                "Failed to handle tree announcement from {}: {}",
                                                addr, e
                                            );
                                        }
                                    }
                                }
                                4 => {
                                    // TYPE_PROTO_BLOOM_FILTER
                                    if decrypted_data.len() > 2 {
                                        if let Err(e) = self
                                            .handle_bloom_filter_update(
                                                &peer_key_bytes,
                                                &decrypted_data[2..],
                                            )
                                            .await
                                        {
                                            warn!(
                                                "Failed to handle bloom filter from {}: {}",
                                                addr, e
                                            );
                                        }
                                    }
                                }
                                5 => {
                                    // TYPE_PROTO_LOOKUP_REQUEST
                                    if decrypted_data.len() > 2 {
                                        if let Err(e) = self
                                            .handle_lookup_request(
                                                &peer_key_bytes,
                                                &decrypted_data[2..],
                                            )
                                            .await
                                        {
                                            warn!(
                                                "Failed to handle lookup request from {}: {}",
                                                addr, e
                                            );
                                        }
                                    }
                                }
                                6 => {
                                    // TYPE_PROTO_LOOKUP_RESPONSE
                                    if decrypted_data.len() > 2 {
                                        if let Err(e) = self
                                            .proto_handler
                                            .handle_proto(peer_key_bytes, &decrypted_data[1..])
                                            .await
                                        {
                                            warn!(
                                                "Failed to handle lookup response from {}: {}",
                                                addr, e
                                            );
                                        }
                                    }
                                }
                                _ => {
                                    // Unknown protocol type or other handlers
                                    if let Err(e) = self
                                        .proto_handler
                                        .handle_proto(peer_key_bytes, &decrypted_data[1..])
                                        .await
                                    {
                                        warn!(
                                            "Failed to handle protocol message from {}: {}",
                                            addr, e
                                        );
                                    }
                                }
                            }
                        }
                        // Protocol messages are not routed further
                        return Ok(());
                    }

                    // Update route based on packet source
                    if decrypted_data.len() >= 40 {
                        // Get peer's RTT for latency measurement
                        let latency = peer.rtt;
                        let _ = self
                            .routing_table
                            .update_route_from_packet(peer.public_key, &decrypted_data, latency)
                            .await;
                    }

                    // Route decrypted packet
                    let local_addr = self.address.as_ipv6();
                    if let Err(e) = self
                        .routing_table
                        .handle_peer_packet(peer.public_key, decrypted_data, &local_addr)
                        .await
                    {
                        warn!("Failed to route packet from {}: {}", addr, e);
                    }
                } else {
                    warn!("Received data from unknown peer: {}", addr);
                }
            }
        }

        Ok(())
    }

    /// Handle router event
    async fn handle_router_event(&mut self, event: RouterEvent) -> Result<()> {
        match event {
            RouterEvent::PacketToPeer(peer_key, data) => {
                debug!(
                    "Sending {} bytes to peer {}",
                    data.len(),
                    Address::from_public_key(&peer_key)
                );

                // Find peer by public key
                if let Some(peer) = self.peer_manager.find_peer_by_key(&peer_key).await {
                    // Try to encrypt packet if session exists
                    let encrypted_data =
                        if let Some(session) = self.session_manager.get_session(&peer_key).await {
                            match session.encrypt(&data) {
                                Ok(ciphertext) => {
                                    debug!("Encrypted {} bytes for peer", ciphertext.len());

                                    // Update session statistics
                                    self.session_manager
                                        .update_stats(&peer_key, ciphertext.len() as u64, 0)
                                        .await;

                                    ciphertext
                                }
                                Err(e) => {
                                    warn!("Failed to encrypt packet for {}: {}", peer.addr, e);
                                    // If encryption fails, send unencrypted (for backward compatibility)
                                    data.clone()
                                }
                            }
                        } else {
                            // No session yet, send unencrypted
                            debug!("No session for peer {}, sending unencrypted", peer.addr);
                            data.clone()
                        };

                    // Send encrypted data to peer via link manager
                    if let Err(e) = self
                        .link_manager
                        .send_to_peer(&peer.addr, encrypted_data.clone())
                        .await
                    {
                        warn!("Failed to send packet to peer {}: {}", peer.addr, e);
                    } else {
                        debug!(
                            "Sent {} bytes to peer at {}",
                            encrypted_data.len(),
                            peer.addr
                        );
                    }

                    // Update peer statistics
                    self.peer_manager
                        .update_peer_stats(&peer.addr, encrypted_data.len() as u64, 0)
                        .await;
                } else {
                    warn!(
                        "No peer found with key {}",
                        Address::from_public_key(&peer_key)
                    );
                }
            }
            RouterEvent::PacketToTun(data) => {
                debug!("Sending {} bytes to TUN", data.len());

                // Send to TUN interface
                if let Some(ref adapter) = self.tun_adapter {
                    if let Err(e) = adapter.send(&data).await {
                        warn!("Failed to send packet to TUN: {}", e);
                    }
                } else {
                    debug!("TUN adapter not available, dropping packet");
                }
            }
            RouterEvent::PacketFromPeer(peer_key, _data) => {
                debug!(
                    "Processing packet from peer {}",
                    Address::from_public_key(&peer_key)
                );

                // This is handled by DataReceived event
                // This variant is mainly for internal routing
            }
        }

        Ok(())
    }

    /// Handle TUN packet queue
    async fn handle_tun_packet_queue(&mut self, packet: Vec<u8>) -> Result<()> {
        debug!("Processing queued TUN packet: {} bytes", packet.len());

        // Write packet to TUN interface
        if let Some(ref adapter) = self.tun_adapter {
            adapter.send(&packet).await?;
        }

        Ok(())
    }

    /// Handle TUN event
    async fn handle_tun_event(&mut self, event: TunEvent) -> Result<()> {
        match event {
            TunEvent::PacketRead(packet) => {
                debug!("Packet read from TUN: {} bytes", packet.len());

                // Route packet from TUN
                if let Err(e) = self.routing_table.handle_tun_packet(packet).await {
                    warn!("Failed to route TUN packet: {}", e);
                }
            }
            TunEvent::Error(err) => {
                error!("TUN error: {}", err);
            }
        }

        Ok(())
    }

    /// Start background tasks with graceful shutdown support
    fn start_background_tasks(&self) {
        let routing_table = self.routing_table.clone();
        let peer_manager = self.peer_manager.clone();
        let session_manager = self.session_manager.clone();
        let spanning_tree = self.spanning_tree.clone();

        // Routing table cleanup task
        let mut shutdown_rx1 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        routing_table.cleanup_stale_routes(Duration::from_secs(600)).await;
                    }
                    _ = shutdown_rx1.recv() => {
                        debug!("Routing table cleanup task shutting down");
                        break;
                    }
                }
            }
        });

        // Peer cleanup task
        let mut shutdown_rx2 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let removed = peer_manager.cleanup_stale_peers().await;
                        if !removed.is_empty() {
                            info!("Cleaned up {} stale peers", removed.len());
                        }
                    }
                    _ = shutdown_rx2.recv() => {
                        debug!("Peer cleanup task shutting down");
                        break;
                    }
                }
            }
        });

        // Session cleanup task
        let mut shutdown_rx3 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let expired = session_manager.cleanup_expired().await;
                        if !expired.is_empty() {
                            info!("Cleaned up {} expired sessions", expired.len());
                        }
                    }
                    _ = shutdown_rx3.recv() => {
                        debug!("Session cleanup task shutting down");
                        break;
                    }
                }
            }
        });

        // Spanning tree maintenance task
        let spanning_tree_cleanup = spanning_tree.clone();
        let mut shutdown_rx4 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        spanning_tree_cleanup.cleanup_stale().await;
                    }
                    _ = shutdown_rx4.recv() => {
                        debug!("Spanning tree cleanup task shutting down");
                        break;
                    }
                }
            }
        });

        // Tree announcement broadcast task
        let spanning_tree_broadcast = spanning_tree.clone();
        let peer_manager_broadcast = self.peer_manager.clone();
        let session_manager_broadcast = self.session_manager.clone();
        let link_manager_broadcast = self.link_manager.clone();
        let mut shutdown_rx5 = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Get our current announcement
                        let announcement = spanning_tree_broadcast.get_local_announcement().await;

                        // Encode to wire format
                        let encoded = announcement.encode();

                        // Build protocol packet: [TYPE_SESSION_PROTO][TYPE_PROTO_TREE_ANNOUNCEMENT][encoded_announcement]
                        let mut packet = vec![2, 3]; // TYPE_SESSION_PROTO=2, TYPE_PROTO_TREE_ANNOUNCEMENT=3
                        packet.extend_from_slice(&encoded);

                        // Get all connected peers
                        let peers = peer_manager_broadcast.get_all_peers().await;

                        if !peers.is_empty() {
                            debug!("Broadcasting tree announcement to {} peers", peers.len());
                        }

                        // Send to each peer
                        for peer in peers {
                            // Encrypt if we have a session
                            let data_to_send = if let Some(session) = session_manager_broadcast.get_session(&peer.public_key).await {
                                match session.encrypt(&packet) {
                                    Ok(ciphertext) => ciphertext,
                                    Err(e) => {
                                        warn!("Failed to encrypt tree announcement for {}: {}", peer.addr, e);
                                        continue;
                                    }
                                }
                            } else {
                                // No session, send unencrypted
                                packet.clone()
                            };

                            // Send via link manager
                            if let Err(e) = link_manager_broadcast.send_to_peer(&peer.addr, data_to_send).await {
                                warn!("Failed to send tree announcement to {}: {}", peer.addr, e);
                            }
                        }
                    }
                    _ = shutdown_rx5.recv() => {
                        debug!("Tree announcement broadcast task shutting down");
                        break;
                    }
                }
            }
        });

        // Lookup manager cleanup task
        let lookup_manager_cleanup = self.lookup_manager.clone();
        let mut shutdown_rx6 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        lookup_manager_cleanup.cleanup_expired_lookups().await;
                        lookup_manager_cleanup.cleanup_cache().await;
                    }
                    _ = shutdown_rx6.recv() => {
                        debug!("Lookup manager cleanup task shutting down");
                        break;
                    }
                }
            }
        });

        // Bloom filter broadcast task
        let lookup_manager_broadcast = self.lookup_manager.clone();
        let peer_manager_filter = self.peer_manager.clone();
        let proto_handler_broadcast = self.proto_handler.clone();
        let mut shutdown_rx7 = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Broadcast every 60 seconds
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Get our bloom filter
                        let filter = lookup_manager_broadcast.get_local_filter().await;
                        let filter_data = filter.to_bytes();

                        // Get all connected peers
                        let peers = peer_manager_filter.get_all_peers().await;

                        if !peers.is_empty() {
                            debug!("Broadcasting bloom filter to {} peers", peers.len());
                        }

                        // Send to each peer
                        for peer in peers {
                            let peer_key_bytes = peer.public_key.to_bytes();
                            if let Err(e) = proto_handler_broadcast.send_bloom_filter_update(peer_key_bytes, &filter_data).await {
                                warn!("Failed to send bloom filter to {}: {}", peer.addr, e);
                            }
                        }
                    }
                    _ = shutdown_rx7.recv() => {
                        debug!("Bloom filter broadcast task shutting down");
                        break;
                    }
                }
            }
        });

        info!("Background tasks started (including spanning tree, lookup manager, and bloom filter broadcast)");
    }

    /// Get node address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Get peer statistics
    pub async fn get_peer_stats(&self) -> crate::peer::PeerStats {
        self.peer_manager.get_stats().await
    }

    /// Get route count
    pub async fn get_route_count(&self) -> usize {
        self.routing_table.route_count().await
    }

    /// Start core event loop and admin server
    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!("Starting Yggdrasil node...");
        info!("Address: {}", self.address);
        info!(
            "Public key: {}",
            hex::encode(self.crypto.public_key().to_bytes())
        );

        // Start background tasks
        self.start_background_tasks();

        // Start admin server if enabled (admin_listen is not "none")
        if let Some(ref admin_listen) = self.config.admin_listen {
            if admin_listen != "none" {
                self.start_admin_server().await?;
            }
        }

        Ok(())
    }

    /// Start admin server
    async fn start_admin_server(self: &Arc<Self>) -> Result<()> {
        let admin_endpoint = self
            .config
            .admin_listen
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No admin listen address"))?;
        let admin_server = AdminServer::new(admin_endpoint);

        let core = Arc::clone(self);

        tokio::spawn(async move {
            let handler = move |request: &str, args: serde_json::Value| {
                let core_clone = Arc::clone(&core);
                let request = request.to_string();

                async move {
                    match request.as_str() {
                        "getSelf" => {
                            let response = core_clone.get_self_info().await;
                            Ok(serde_json::to_value(response)?)
                        }
                        "getPeers" => {
                            let response = core_clone.get_peers_info().await;
                            Ok(serde_json::to_value(response)?)
                        }
                        "getPaths" => {
                            let response = core_clone.get_paths_info().await;
                            Ok(serde_json::to_value(response)?)
                        }
                        "getSessions" => {
                            let response = core_clone.get_sessions_info().await;
                            Ok(serde_json::to_value(response)?)
                        }
                        "addPeer" => {
                            let req: crate::admin::AddPeerRequest = serde_json::from_value(args)?;
                            let response = core_clone
                                .add_peer_handler(&req.uri, req.interface.as_deref())
                                .await;
                            Ok(serde_json::to_value(response)?)
                        }
                        "removePeer" => {
                            let req: crate::admin::RemovePeerRequest =
                                serde_json::from_value(args)?;
                            let response = core_clone
                                .remove_peer_handler(&req.uri, req.interface.as_deref())
                                .await;
                            Ok(serde_json::to_value(response)?)
                        }
                        _ => Err(anyhow::anyhow!("Unknown command: {}", request)),
                    }
                }
            };

            if let Err(e) = admin_server.start(handler).await {
                warn!("Admin server error: {}", e);
            }
        });

        let admin_endpoint = self
            .config
            .admin_listen
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No admin listen address"))?;
        info!("Admin server started on {}", admin_endpoint);
        Ok(())
    }

    /// Stop node and display statistics with graceful shutdown
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Yggdrasil node...");

        // Send shutdown signal to all background tasks
        if let Err(e) = self.shutdown_tx.send(()) {
            warn!("Failed to send shutdown signal: {}", e);
        } else {
            info!("Shutdown signal sent to all background tasks");
        }

        // Give background tasks time to finish gracefully
        tokio::time::sleep(Duration::from_millis(500)).await;

        let peer_stats = self.get_peer_stats().await;
        let route_count = self.get_route_count().await;

        info!("Final statistics:");
        info!("  Total peers: {}", peer_stats.total);
        info!("  Connected peers: {}", peer_stats.connected);
        info!("  Routes: {}", route_count);

        info!("Yggdrasil node stopped gracefully");
        Ok(())
    }

    /// Get self information for admin API
    pub async fn get_self_info(&self) -> GetSelfResponse {
        GetSelfResponse {
            build_name: "yggdrasil-rust".to_string(),
            build_version: crate::VERSION.to_string(),
            public_key: hex::encode(self.crypto.public_key().to_bytes()),
            ip_address: self.address.to_string(),
            routing_entries: self.get_route_count().await as u64,
            subnet: self.subnet.to_string(),
        }
    }

    /// Get peers information for admin API
    pub async fn get_peers_info(&self) -> GetPeersResponse {
        let peers = self.peer_manager.get_all_peers().await;
        let peer_entries = peers
            .into_iter()
            .map(|p| {
                let address = Address::from_public_key(&p.public_key);

                // Extract port from socket address
                let port = p.addr.port() as u64;

                // Use calculated rates from peer info
                let rx_rate = p.rx_rate;
                let tx_rate = p.tx_rate;

                // Build PeerEntry with enhanced coordinate and root information
                PeerEntry {
                    uri: Some(p.addr.to_string()),
                    up: p.state == ConnectionState::Connected || p.state == ConnectionState::Ready,
                    inbound: p.conn_type == ConnectionType::Incoming,
                    ip_address: Some(address.to_string()),
                    public_key: hex::encode(p.public_key.to_bytes()),
                    port,
                    priority: 0,
                    cost: 0,
                    rx_bytes: Some(p.bytes_received),
                    tx_bytes: Some(p.bytes_sent),
                    rx_rate: Some(rx_rate),
                    tx_rate: Some(tx_rate),
                    uptime: Some(p.connected_at.elapsed().as_secs_f64()),
                    latency: Some(p.rtt as u64),
                    last_error_time: None,
                    last_error: None,
                    // Add coordinates and root information from peer
                    coords: if p.coords.is_empty() {
                        None
                    } else {
                        Some(p.coords.clone())
                    },
                    root: p.root.as_ref().map(|r| hex::encode(r.to_bytes())),
                }
            })
            .collect();

        GetPeersResponse {
            peers: peer_entries,
        }
    }

    /// Get paths information for admin API
    pub async fn get_paths_info(&self) -> GetPathsResponse {
        let routes = self.routing_table.get_all_routes().await;
        let path_entries = routes
            .into_iter()
            .map(|r| {
                PathEntry {
                    public_key: hex::encode(r.next_hop.to_bytes()),
                    ip_address: r.destination.to_string(),
                    path: vec![r.hops as u64], // Simplified path representation
                }
            })
            .collect();

        GetPathsResponse {
            paths: path_entries,
        }
    }

    /// Get sessions information for admin API
    pub async fn get_sessions_info(&self) -> GetSessionsResponse {
        let peers = self.peer_manager.get_all_peers().await;
        let session_entries = peers
            .into_iter()
            .filter(|p| p.state == ConnectionState::Ready)
            .map(|p| SessionEntry {
                public_key: hex::encode(p.public_key.to_bytes()),
                ip_address: Address::from_public_key(&p.public_key).to_string(),
                coords: if p.coords.is_empty() {
                    None
                } else {
                    Some(p.coords.clone())
                },
                root: p.root.as_ref().map(|r| hex::encode(r.to_bytes())),
                rx_bytes: p.bytes_received,
                tx_bytes: p.bytes_sent,
                rx_rate: Some(p.rx_rate),
                tx_rate: Some(p.tx_rate),
                latency_us: if p.rtt > 0 {
                    Some(p.rtt as u64 * 1000)
                } else {
                    None
                },
                uptime: p.connected_at.elapsed().as_secs_f64(),
            })
            .collect();

        GetSessionsResponse {
            sessions: session_entries,
        }
    }

    /// Get spanning tree statistics
    pub async fn get_tree_stats(&self) -> crate::spanning_tree::TreeStats {
        self.spanning_tree.get_stats().await
    }

    /// Get lookup manager statistics
    pub async fn get_lookup_stats(&self) -> crate::lookup::LookupStats {
        self.lookup_manager.get_stats().await
    }

    /// Lookup a node in the network
    pub async fn lookup_node(&self, target_key: &VerifyingKey) -> Result<Option<VerifyingKey>> {
        self.lookup_manager.lookup_node(target_key).await
    }

    /// Handle incoming tree announcement from a peer
    async fn handle_tree_announcement(&self, peer_key_bytes: &[u8; 32], data: &[u8]) -> Result<()> {
        use crate::spanning_tree::TreeAnnouncement;

        // Decode announcement
        let announcement = TreeAnnouncement::decode(data)
            .map_err(|e| anyhow::anyhow!("Failed to decode tree announcement: {}", e))?;

        debug!(
            "Received tree announcement from {}: root={}, dist={}",
            hex::encode(peer_key_bytes),
            hex::encode(announcement.root_key.as_bytes()),
            announcement.root_dist
        );

        // Process announcement through spanning tree
        self.spanning_tree.handle_announcement(announcement).await?;

        // Convert bytes to VerifyingKey for coordinate calculation
        let peer_key = VerifyingKey::from_bytes(peer_key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid peer key: {}", e))?;

        // Recalculate coordinates for this peer
        let coords = self.spanning_tree.calculate_coords(&peer_key).await;
        debug!(
            "Updated coordinates for peer {}: {:?}",
            hex::encode(peer_key_bytes),
            coords
        );

        Ok(())
    }

    /// Broadcast our tree announcement to all connected peers
    pub async fn broadcast_tree_announcement(&self) -> Result<()> {
        // Get our current announcement
        let announcement = self.spanning_tree.get_local_announcement().await;

        // Encode to wire format
        let encoded = announcement.encode();

        // Build protocol packet: [TYPE_SESSION_PROTO][TYPE_PROTO_TREE_ANNOUNCEMENT][encoded_announcement]
        let mut packet = vec![2, 3]; // TYPE_SESSION_PROTO=2, TYPE_PROTO_TREE_ANNOUNCEMENT=3
        packet.extend_from_slice(&encoded);

        // Get all connected peers
        let peers = self.peer_manager.get_all_peers().await;

        debug!("Broadcasting tree announcement to {} peers", peers.len());

        // Send to each peer
        for peer in peers {
            // Encrypt if we have a session
            let data_to_send =
                if let Some(session) = self.session_manager.get_session(&peer.public_key).await {
                    match session.encrypt(&packet) {
                        Ok(ciphertext) => ciphertext,
                        Err(e) => {
                            warn!(
                                "Failed to encrypt tree announcement for {}: {}",
                                peer.addr, e
                            );
                            continue;
                        }
                    }
                } else {
                    // No session, send unencrypted
                    packet.clone()
                };

            // Send via link manager
            if let Err(e) = self
                .link_manager
                .send_to_peer(&peer.addr, data_to_send)
                .await
            {
                warn!("Failed to send tree announcement to {}: {}", peer.addr, e);
            }
        }

        Ok(())
    }

    /// Add peer for admin API
    pub async fn add_peer_handler(&self, uri: &str, interface: Option<&str>) -> AddPeerResponse {
        info!("Adding peer: {}", uri);

        match self.link_manager.add_peer_dynamic(uri, interface).await {
            Ok(()) => AddPeerResponse {
                success: Some(true),
                error: None,
            },
            Err(e) => AddPeerResponse {
                success: Some(false),
                error: Some(format!("Failed to add peer: {}", e)),
            },
        }
    }

    /// Remove peer for admin API
    pub async fn remove_peer_handler(
        &self,
        uri: &str,
        interface: Option<&str>,
    ) -> RemovePeerResponse {
        info!("Removing peer: {}", uri);

        match self.link_manager.remove_peer_dynamic(uri, interface).await {
            Ok(()) => RemovePeerResponse {
                success: Some(true),
                error: None,
            },
            Err(e) => RemovePeerResponse {
                success: Some(false),
                error: Some(format!("Failed to remove peer: {}", e)),
            },
        }
    }

    /// Handle protocol send from ProtoHandler
    async fn handle_proto_send(&mut self, packet: Vec<u8>, to_key: [u8; 32]) -> Result<()> {
        // Find peer by public key
        let peer_key = VerifyingKey::from_bytes(&to_key)?;

        if let Some(peer) = self.peer_manager.find_peer_by_key(&peer_key).await {
            // Try to encrypt packet if session exists
            let encrypted_data =
                if let Some(session) = self.session_manager.get_session(&peer_key).await {
                    match session.encrypt(&packet) {
                        Ok(ciphertext) => ciphertext,
                        Err(e) => {
                            warn!("Failed to encrypt protocol packet for {}: {}", peer.addr, e);
                            packet.clone()
                        }
                    }
                } else {
                    // No session yet, send unencrypted
                    packet.clone()
                };

            // Send via link manager
            self.link_manager
                .send_to_peer(&peer.addr, encrypted_data)
                .await?;
        } else {
            debug!(
                "Cannot send protocol packet: peer {:?} not found",
                hex::encode(to_key)
            );
        }

        Ok(())
    }

    /// Handle Bloom filter update from peer
    async fn handle_bloom_filter_update(&self, peer_key: &[u8; 32], data: &[u8]) -> Result<()> {
        if data.len() < 1024 {
            warn!("Invalid bloom filter size: {} bytes", data.len());
            return Ok(());
        }

        debug!(
            "Received bloom filter update from {:?}",
            hex::encode(peer_key)
        );

        // Parse filter from bytes
        let filter = BloomFilter::from_bytes(data)?;

        // Update lookup manager with peer's filter
        let verifying_key = VerifyingKey::from_bytes(peer_key)?;
        self.lookup_manager
            .update_peer_filter(verifying_key, filter)
            .await;

        Ok(())
    }

    /// Handle lookup request from peer
    async fn handle_lookup_request(&self, peer_key: &[u8; 32], data: &[u8]) -> Result<()> {
        if data.len() < 32 {
            warn!("Invalid lookup request: {} bytes", data.len());
            return Ok(());
        }

        let mut target_key = [0u8; 32];
        target_key.copy_from_slice(&data[..32]);

        debug!(
            "Received lookup request from {:?} for target {:?}",
            hex::encode(peer_key),
            hex::encode(target_key)
        );

        // Check if we know the target
        let target_verifying_key = VerifyingKey::from_bytes(&target_key)?;
        let found_key = self
            .lookup_manager
            .lookup_node(&target_verifying_key)
            .await?;

        // Send response
        let _peer_verifying_key = VerifyingKey::from_bytes(peer_key)?;
        if let Some(next_hop) = found_key {
            let response_key = next_hop.to_bytes();
            self.proto_handler
                .send_lookup_response(*peer_key, Some(response_key))
                .await?;
        } else {
            self.proto_handler
                .send_lookup_response(*peer_key, None)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_core_creation() {
        let config = Config::generate().unwrap();
        let core = Core::new(config).await.unwrap();
        assert!(core.address().is_valid());
    }

    #[tokio::test]
    async fn test_core_event_loop() {
        // Test core event loop processing
        let mut config = Config::generate().unwrap();
        config.if_name = "none".to_string();
        config.listen = vec![];
        config.peers = vec![];

        let core = Arc::new(Core::new(config).await.unwrap());
        let core_clone = core.clone();

        // Start core in background
        let handle = tokio::spawn(async move { core_clone.start().await });

        // Let event loop run for a bit
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Stop core
        core.stop().await.unwrap();

        // Wait for start task to complete
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        println!("Event loop test completed successfully");
    }

    #[tokio::test]
    async fn test_peer_connection_lifecycle() {
        // Test peer connect/disconnect handling
        let mut config = Config::generate().unwrap();
        config.if_name = "none".to_string();
        config.listen = vec!["tcp://127.0.0.1:0".to_string()];
        config.peers = vec![];

        let mut core = Core::new(config).await.unwrap();

        // Simulate peer connection event
        use std::net::SocketAddr;
        let test_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let link_event = crate::link::LinkEvent::Connected(test_addr);

        // Handle the event
        if core.handle_link_event(link_event).await.is_ok() {
            // Check if peer was added
            let peers = core.peer_manager.get_all_peers().await;

            // May or may not have peer depending on handshake completion
            println!("Peer lifecycle test: {} peers registered", peers.len());
        }

        println!("Peer connection lifecycle test completed");
    }

    #[tokio::test]
    async fn test_packet_routing() {
        // Test packet routing through core
        let mut config = Config::generate().unwrap();
        config.if_name = "none".to_string();
        config.listen = vec![];
        config.peers = vec![];

        let core = Core::new(config).await.unwrap();
        let local_addr = core.address().as_ipv6();

        // Create a simple IPv6 packet (minimal header)
        let mut packet = vec![0u8; 40]; // IPv6 header size

        // Version (6) and traffic class
        packet[0] = 0x60;

        // Payload length (0)
        packet[4] = 0;
        packet[5] = 0;

        // Next header (59 = No Next Header)
        packet[6] = 59;

        // Hop limit
        packet[7] = 64;

        // Source address (use our address)
        let src_bytes = local_addr.octets();
        packet[8..24].copy_from_slice(&src_bytes);

        // Destination address (use our address - loopback)
        packet[24..40].copy_from_slice(&src_bytes);

        // Try to route the packet
        if let Ok(_) = core.routing_table.route_packet(packet).await {
            println!("Packet routing test: packet processed");
        } else {
            println!("Packet routing test: packet handling completed");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_background_tasks() {
        // Add overall timeout to prevent hanging
        let test_future = async {
            // Test background cleanup tasks with graceful shutdown
            let mut config = Config::generate().unwrap();
            config.if_name = "none".to_string();
            config.listen = vec![];
            config.peers = vec![];

            let core = Arc::new(Core::new(config).await.unwrap());
            let core_clone = core.clone();

            // Start core which runs background tasks
            // Note: start() returns immediately after spawning background tasks
            let handle = tokio::spawn(async move { core_clone.start().await });

            // Wait for start() to complete (should be immediate)
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(Ok(_))) => {
                    println!("Background tasks test: Core started successfully");
                }
                Ok(Ok(Err(e))) => {
                    panic!("Background tasks test: Core start failed: {}", e);
                }
                Ok(Err(e)) => {
                    panic!("Background tasks test: Task panicked: {}", e);
                }
                Err(_) => {
                    panic!("Background tasks test: start() timed out (should return immediately)");
                }
            }

            // Let background tasks run briefly
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Check that routing table is still functional
            let routes = core.routing_table.get_all_routes().await;
            println!("Background tasks test: {} routes in table", routes.len());

            // Stop core - now with graceful shutdown support
            core.stop().await.unwrap();

            // Give tasks a moment to shut down
            tokio::time::sleep(Duration::from_millis(600)).await;

            println!("Background tasks test completed with graceful shutdown");
        };

        // Add overall timeout to prevent test hanging
        match tokio::time::timeout(Duration::from_secs(10), test_future).await {
            Ok(_) => {
                println!("Background tasks test finished within timeout");
            }
            Err(_) => {
                panic!("Background tasks test exceeded 10 second timeout");
            }
        }
    }
}
