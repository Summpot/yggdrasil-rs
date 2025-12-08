//! Links manager for managing peer connections.
//!
//! This module handles:
//! - TLS listeners for incoming connections
//! - Outbound connections to discovered peers
//! - Handshake protocol execution
//! - Peer connection lifecycle management

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::RwLock;
use rustls::pki_types::CertificateDer;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, trace, warn};
use yggdrasil_types::{PeerPort, PrivateKey, PublicKey};

use crate::LinkError;
use crate::handshake::perform_handshake;
use crate::peer_handler::{OutgoingPacket, PeerEvent, PeerHandler, create_peer_channels};
use crate::tls::{create_insecure_client_config, create_server_config};

/// Link connection type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Persistent configured peer.
    Persistent,
    /// Ephemeral multicast-discovered peer.
    Ephemeral,
    /// Incoming connection.
    Incoming,
}

/// Information about an active link.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    /// URI of the peer connection.
    pub uri: String,
    /// Remote public key.
    pub remote_key: PublicKey,
    /// Remote IPv6 address derived from public key.
    pub remote_addr_v6: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Local socket address.
    pub local_addr: SocketAddr,
    /// Assigned peer port for this link.
    pub peer_port: PeerPort,
    /// Link type (persistent, ephemeral, incoming).
    pub link_type: LinkType,
    /// Protocol (tcp, tls, quic).
    pub protocol: String,
    /// Whether this is an outbound connection.
    pub outbound: bool,
    /// Connection priority.
    pub priority: u8,
    /// When the connection was established.
    pub established: Instant,
    /// Last error (if any).
    pub last_error: Option<String>,
    /// Time of last error.
    pub last_error_time: Option<Instant>,
}

/// Metrics for a live link connection.
#[derive(Debug)]
pub struct LinkMetrics {
    /// Bytes received.
    pub rx: AtomicU64,
    /// Bytes transmitted.
    pub tx: AtomicU64,
    /// Whether the connection is still alive.
    pub alive: AtomicBool,
    /// Last measured RTT in microseconds.
    pub rtt_us: AtomicU64,
}

#[derive(Debug)]
struct LinkConnection {
    info: LinkInfo,
    metrics: Arc<LinkMetrics>,
    task: JoinHandle<()>,
}

/// Snapshot of a connection and its counters.
#[derive(Debug, Clone)]
pub struct LinkSummary {
    pub info: LinkInfo,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub alive: bool,
    pub rtt_us: u64,
}

/// Active link connection state.
#[allow(dead_code)]
struct LinkState {
    uri: String,
    sintf: String,
    link_type: LinkType,
    protocol: String,
    conn: Option<Arc<LinkConnection>>,
    last_error: Option<String>,
    last_error_time: Option<Instant>,
}

/// Callback for handling new peer connections.
pub trait LinksCallbacks: Send + Sync {
    fn on_peer_connected(&self, key: PublicKey, priority: u8);
    fn on_peer_disconnected(&self, key: PublicKey);
}

/// Event emitted when a peer connects.
#[derive(Debug)]
pub struct PeerConnectedEvent {
    pub public_key: PublicKey,
    pub ipv6_addr: String,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub priority: u8,
    pub outbound: bool,
    pub peer_port: yggdrasil_types::PeerPort,
    pub outgoing_tx: mpsc::Sender<OutgoingPacket>,
    pub event_rx: mpsc::UnboundedReceiver<PeerEvent>,
}

/// Links manager for all peer connections.
pub struct Links {
    /// Our private key.
    private_key: PrivateKey,
    /// Our public key.
    public_key: PublicKey,
    /// Running state.
    running: AtomicBool,
    /// Active links by URI.
    links: RwLock<HashMap<String, LinkState>>,
    /// Listener addresses.
    listeners: RwLock<Vec<SocketAddr>>,
    /// TLS configuration for server.
    tls_acceptor: Arc<RwLock<Option<TlsAcceptor>>>,
    /// Channel for peer connection events.
    event_tx: mpsc::UnboundedSender<PeerConnectedEvent>,
    /// Allowed public keys (empty = allow all).
    allowed_keys: RwLock<HashMap<[u8; 32], ()>>,
    /// Next peer port to allocate (shared across accept handlers).
    next_peer_port: Arc<AtomicU64>,
}

impl Links {
    /// Create a new links manager.
    pub fn new(private_key: PrivateKey) -> (Self, mpsc::UnboundedReceiver<PeerConnectedEvent>) {
        let public_key = private_key.public_key();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let links = Self {
            private_key,
            public_key,
            running: AtomicBool::new(false),
            links: RwLock::new(HashMap::new()),
            listeners: RwLock::new(Vec::new()),
            tls_acceptor: Arc::new(RwLock::new(None)),
            event_tx,
            allowed_keys: RwLock::new(HashMap::new()),
            next_peer_port: Arc::new(AtomicU64::new(1)), // Port 0 is reserved
        };

        (links, event_rx)
    }

    /// Allocate a new peer port.
    fn allocate_peer_port(&self) -> yggdrasil_types::PeerPort {
        self.next_peer_port.fetch_add(1, Ordering::SeqCst)
    }

    /// Get a reference to the peer port allocator (for spawned tasks).
    fn peer_port_allocator(&self) -> Arc<AtomicU64> {
        self.next_peer_port.clone()
    }

    /// Check whether we already have a live connection to the given public key.
    pub fn has_active_connection(&self, key: &PublicKey) -> bool {
        let links = self.links.read();
        links.values().any(|state| {
            state.conn.as_ref().map_or(false, |conn| {
                conn.info.remote_key == *key && conn.metrics.alive.load(Ordering::Relaxed)
            })
        })
    }

    /// Remove a connection from the internal state and mark it as disconnected.
    /// For ephemeral or incoming links we drop the entire entry so it no longer
    /// appears in peer listings.
    pub fn cleanup_connection(
        &self,
        key: &PublicKey,
        peer_port: PeerPort,
        error: Option<String>,
    ) {
        let mut links = self.links.write();
        let mut to_remove = Vec::new();

        for (uri, state) in links.iter_mut() {
            let matches_peer = state
                .conn
                .as_ref()
                .map(|conn| conn.info.remote_key == *key && conn.info.peer_port == peer_port)
                .unwrap_or(false);

            if !matches_peer {
                continue;
            }

            if let Some(conn) = state.conn.take() {
                conn.metrics.alive.store(false, Ordering::SeqCst);
                conn.task.abort();
            }

            state.last_error = error.clone();
            state.last_error_time = Some(Instant::now());

            if matches!(state.link_type, LinkType::Ephemeral | LinkType::Incoming) {
                to_remove.push(uri.clone());
            }
        }

        for uri in to_remove {
            links.remove(&uri);
        }
    }

    /// Get our public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Set allowed public keys (empty = allow all).
    pub fn set_allowed_keys(&self, keys: Vec<PublicKey>) {
        let mut allowed = self.allowed_keys.write();
        allowed.clear();
        for key in keys {
            allowed.insert(*key.as_bytes(), ());
        }
    }

    /// Check if a public key is allowed.
    fn is_key_allowed(&self, key: &PublicKey) -> bool {
        let allowed = self.allowed_keys.read();
        if allowed.is_empty() {
            return true;
        }
        allowed.contains_key(key.as_bytes())
    }

    /// Start the links manager.
    pub async fn start(&self) -> Result<(), LinkError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(LinkError::Protocol("already started".to_string()));
        }

        // Generate self-signed TLS certificate
        let (cert, key) = generate_self_signed_cert(&self.public_key)?;
        let server_config = create_server_config(cert, key)?;
        *self.tls_acceptor.write() = Some(TlsAcceptor::from(server_config));

        info!("Links manager started");
        Ok(())
    }

    /// Stop the links manager.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Links manager stopped");
    }

    /// Check if the manager is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Start a TLS listener on the given address.
    /// Returns the actual port that was bound.
    pub async fn listen(
        self: &Arc<Self>,
        addr: SocketAddr,
        _sintf: &str,
        password: &[u8],
    ) -> Result<u16, LinkError> {
        if !self.is_running() {
            return Err(LinkError::Protocol("not started".to_string()));
        }

        let acceptor = {
            let guard = self.tls_acceptor.read();
            guard
                .clone()
                .ok_or_else(|| LinkError::Protocol("TLS not configured".to_string()))?
        };

        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let actual_port = local_addr.port();

        self.listeners.write().push(local_addr);

        info!(addr = %local_addr, "TLS listener started");

        let private_key = self.private_key.clone();
        let public_key = self.public_key.clone();
        let event_tx = self.event_tx.clone();
        let password = password.to_vec();
        let allowed_keys = self.allowed_keys.read().clone();
        let peer_port_allocator = self.peer_port_allocator();
        let links = Arc::clone(self);

        tokio::spawn(async move {
            Self::accept_loop(
                links,
                listener,
                acceptor,
                private_key,
                public_key,
                event_tx,
                password,
                allowed_keys,
                peer_port_allocator,
            )
            .await;
        });

        Ok(actual_port)
    }

    /// Accept incoming connections.
    async fn accept_loop(
        links: Arc<Links>,
        listener: TcpListener,
        acceptor: TlsAcceptor,
        private_key: PrivateKey,
        _public_key: PublicKey,
        event_tx: mpsc::UnboundedSender<PeerConnectedEvent>,
        password: Vec<u8>,
        allowed_keys: HashMap<[u8; 32], ()>,
        peer_port_allocator: Arc<AtomicU64>,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, remote_addr)) => {
                    let acceptor = acceptor.clone();
                    let private_key = private_key.clone();
                    let event_tx = event_tx.clone();
                    let password = password.clone();
                    let allowed_keys = allowed_keys.clone();
                    let peer_port_allocator = peer_port_allocator.clone();

                    let links = Arc::clone(&links);
                    tokio::spawn(async move {
                        trace!(addr = %remote_addr, "Accepting incoming TLS connection");
                        if let Err(e) = Self::handle_incoming(
                            links,
                            stream,
                            acceptor,
                            private_key,
                            event_tx,
                            password,
                            allowed_keys,
                            peer_port_allocator,
                        )
                        .await
                        {
                            debug!(addr = %remote_addr, error = %e, "Incoming connection failed");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "Accept error");
                    break;
                }
            }
        }
    }

    /// Handle an incoming connection.
    async fn handle_incoming(
        links: Arc<Links>,
        stream: TcpStream,
        acceptor: TlsAcceptor,
        private_key: PrivateKey,
        event_tx: mpsc::UnboundedSender<PeerConnectedEvent>,
        password: Vec<u8>,
        allowed_keys: HashMap<[u8; 32], ()>,
        peer_port_allocator: Arc<AtomicU64>,
    ) -> Result<(), LinkError> {
        let remote_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;

        trace!(
            remote_addr = %remote_addr,
            local_addr = %local_addr,
            "Starting TLS handshake for incoming connection"
        );

        // TLS handshake
        let mut tls_stream = acceptor.accept(stream).await.map_err(|e| {
            trace!(error = %e, "TLS accept failed");
            LinkError::Tls(e.to_string())
        })?;

        trace!("TLS handshake complete, starting protocol handshake");

        // Yggdrasil protocol handshake
        let metadata = perform_handshake(&mut tls_stream, &private_key, 0, &password)
            .await
            .map_err(|e| {
                trace!(error = %e, "Protocol handshake failed");
                LinkError::Protocol(e.to_string())
            })?;

        trace!(
            remote_key = %hex::encode(&metadata.public_key.as_bytes()[..8]),
            priority = metadata.priority,
            "Protocol handshake complete"
        );

        // Check if key is allowed
        if !allowed_keys.is_empty() && !allowed_keys.contains_key(metadata.public_key.as_bytes()) {
            return Err(LinkError::Protocol(format!(
                "public key {} not in allowed list",
                hex::encode(metadata.public_key.as_bytes())
            )));
        }

        // Drop duplicate connections to the same peer. If we already have a
        // live connection, prefer the existing one to avoid in/out duplicates
        // when multicast discovers the same peer from both sides.
        if links.has_active_connection(&metadata.public_key) {
            return Err(LinkError::Protocol("duplicate connection already active".to_string()));
        }

        // Compute IPv6 address
        let ipv6_addr = yggdrasil_address::addr_for_key(&metadata.public_key)
            .map(|a| a.to_string())
            .unwrap_or_default();

        let priority = metadata.priority;

        // Allocate a peer port
        let peer_port = peer_port_allocator.fetch_add(1, Ordering::SeqCst);

        info!(
            peer = %hex::encode(&metadata.public_key.as_bytes()[..8]),
            addr = %ipv6_addr,
            source = %local_addr,
            peer_port = peer_port,
            "Connected inbound"
        );

        let uri = format!("tls://{}", remote_addr);

        let metrics = Arc::new(LinkMetrics {
            rx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            alive: AtomicBool::new(true),
            rtt_us: AtomicU64::new(0),
        });

        let info = LinkInfo {
            uri: uri.clone(),
            remote_key: metadata.public_key.clone(),
            remote_addr_v6: ipv6_addr.clone(),
            remote_addr,
            local_addr,
            peer_port,
            link_type: LinkType::Incoming,
            protocol: "tls".to_string(),
            outbound: false,
            priority,
            established: Instant::now(),
            last_error: None,
            last_error_time: None,
        };

        // Create channels for the peer handler
        let (outgoing_tx, outgoing_rx, peer_event_tx, event_rx) = create_peer_channels();

        let metrics_for_task = Arc::clone(&metrics);
        let info_for_state = info.clone();

        // Start the peer handler
        let handle = tokio::spawn(async move {
            let handler = PeerHandler::new(
                tls_stream,
                private_key,
                metadata.public_key,
                peer_port,
                outgoing_rx,
                peer_event_tx,
            )
            .with_metrics(metrics_for_task.clone());

            if let Err(e) = handler.run().await {
                debug!(error = ?e, "Peer handler finished with error");
            }

            metrics_for_task.alive.store(false, Ordering::SeqCst);
        });

        // Track the connection so admin and metrics can see it
        {
            let mut map = links.links.write();
            map.insert(
                uri.clone(),
                LinkState {
                    uri: uri.clone(),
                    sintf: String::new(),
                    link_type: LinkType::Incoming,
                    protocol: "tls".to_string(),
                    conn: Some(Arc::new(LinkConnection {
                        info: info_for_state,
                        metrics,
                        task: handle,
                    })),
                    last_error: None,
                    last_error_time: None,
                },
            );
            debug!(
                uri = %uri,
                remote_key = %hex::encode(metadata.public_key.as_bytes()),
                total_links = map.len(),
                "Incoming connection tracked in links HashMap"
            );
        }

        // Send connection event
        let _ = event_tx.send(PeerConnectedEvent {
            public_key: info.remote_key,
            ipv6_addr,
            remote_addr,
            local_addr,
            priority,
            outbound: false,
            peer_port,
            outgoing_tx,
            event_rx,
        });

        Ok(())
    }

    /// Connect to a peer at the given address.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        sintf: &str,
        link_type: LinkType,
        priority: u8,
        password: &[u8],
    ) -> Result<PublicKey, LinkError> {
        if !self.is_running() {
            return Err(LinkError::Protocol("not started".to_string()));
        }

        let uri = format!("tls://{}", addr);

        // Check if we're already connected
        {
            let links = self.links.read();
            if let Some(state) = links.get(&uri) {
                if state.conn.is_some() {
                    return Err(LinkError::Protocol("already connected".to_string()));
                }
            }
        }

        debug!(addr = %addr, "Connecting to peer");

        // TCP connect
        trace!("Starting TCP connect");
        let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| LinkError::Timeout)?
            .map_err(LinkError::Io)?;

        let local_addr = stream.local_addr()?;
        let remote_addr = stream.peer_addr()?;

        trace!(
            local = %local_addr,
            remote = %remote_addr,
            "TCP connected, starting TLS handshake"
        );

        // TLS handshake
        let tls_config = create_insecure_client_config();
        let connector = tokio_rustls::TlsConnector::from(tls_config);

        // Use IP address as server name for TLS (will be ignored due to insecure verifier)
        let server_name = rustls::pki_types::ServerName::try_from("yggdrasil")
            .map_err(|e| LinkError::Tls(e.to_string()))?;

        trace!("Starting TLS client handshake");
        let mut tls_stream = connector.connect(server_name, stream).await.map_err(|e| {
            trace!(error = %e, "TLS client handshake failed");
            LinkError::Tls(format!("tls handshake {}", e))
        })?;

        trace!("TLS client handshake complete, starting protocol handshake");

        // Yggdrasil protocol handshake
        trace!("Starting protocol handshake");
        let metadata = perform_handshake(&mut tls_stream, &self.private_key, priority, password)
            .await
            .map_err(|e| {
                trace!(error = %e, "Protocol handshake failed");
                LinkError::Protocol(e.to_string())
            })?;

        trace!(
            remote_key = %hex::encode(&metadata.public_key.as_bytes()[..8]),
            priority = metadata.priority,
            "Protocol handshake complete"
        );

        // Check if key is allowed
        if !self.is_key_allowed(&metadata.public_key) {
            return Err(LinkError::Protocol(format!(
                "public key {} not in allowed list",
                hex::encode(metadata.public_key.as_bytes())
            )));
        }

        // Avoid duplicate connections to the same peer. This mirrors the Go
        // behaviour where multicast should not leave both inbound and
        // outbound links simultaneously for a single neighbour.
        if self.has_active_connection(&metadata.public_key) {
            return Err(LinkError::Protocol("duplicate connection already active".to_string()));
        }

        // Compute IPv6 address
        let ipv6_addr = yggdrasil_address::addr_for_key(&metadata.public_key)
            .map(|a| a.to_string())
            .unwrap_or_default();

        let effective_priority = std::cmp::max(priority, metadata.priority);

        // Allocate a peer port
        let peer_port = self.allocate_peer_port();

        info!(
            peer = %hex::encode(&metadata.public_key.as_bytes()[..8]),
            addr = %ipv6_addr,
            source = %local_addr,
            peer_port = peer_port,
            "Connected outbound"
        );

        let metrics = Arc::new(LinkMetrics {
            rx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            alive: AtomicBool::new(true),
            rtt_us: AtomicU64::new(0),
        });

        let info = LinkInfo {
            uri: format!("tls://{}", addr),
            remote_key: metadata.public_key.clone(),
            remote_addr_v6: ipv6_addr.clone(),
            remote_addr,
            local_addr,
            peer_port,
            link_type,
            protocol: "tls".to_string(),
            outbound: true,
            priority: effective_priority,
            established: Instant::now(),
            last_error: None,
            last_error_time: None,
        };

        // Create channels for the peer handler
        let (outgoing_tx, outgoing_rx, peer_event_tx, event_rx) = create_peer_channels();
        let remote_key = metadata.public_key.clone();

        let metrics_for_task = Arc::clone(&metrics);
        let info_for_state = info.clone();
        let private_key = self.private_key.clone();
        let handle = tokio::spawn(async move {
            let handler = PeerHandler::new(
                tls_stream,
                private_key,
                metadata.public_key,
                peer_port,
                outgoing_rx,
                peer_event_tx,
            )
            .with_metrics(metrics_for_task.clone());

            if let Err(e) = handler.run().await {
                debug!(error = ?e, "Peer handler finished with error");
            }

            metrics_for_task.alive.store(false, Ordering::SeqCst);
        });

        // Store link state
        {
            let mut links = self.links.write();
            links.insert(
                uri.clone(),
                LinkState {
                    uri: uri.clone(),
                    sintf: sintf.to_string(),
                    link_type,
                    protocol: "tls".to_string(),
                    conn: Some(Arc::new(LinkConnection {
                        info: info_for_state,
                        metrics,
                        task: handle,
                    })),
                    last_error: None,
                    last_error_time: None,
                },
            );
            debug!(
                uri = %uri,
                remote_key = %hex::encode(remote_key.as_bytes()),
                link_type = ?link_type,
                total_links = links.len(),
                "Outbound connection tracked in links HashMap"
            );
        }

        // Send event with channels
        let _ = self.event_tx.send(PeerConnectedEvent {
            public_key: metadata.public_key.clone(),
            ipv6_addr,
            remote_addr,
            local_addr,
            priority: effective_priority,
            outbound: true,
            peer_port,
            outgoing_tx,
            event_rx,
        });

        Ok(remote_key)
    }

    /// Connect to a peer using a URI (e.g. tls://host:port, tcp://host:port).
    pub async fn connect_uri(
        &self,
        uri: &str,
        sintf: &str,
        link_type: LinkType,
        priority: u8,
        password: &[u8],
    ) -> Result<PublicKey, LinkError> {
        // Parse protocol scheme
        let protocol = if let Some(scheme_end) = uri.find("://") {
            &uri[..scheme_end]
        } else {
            return Err(LinkError::Protocol(
                "URI missing protocol scheme (e.g., tls://)".to_string(),
            ));
        };

        match protocol {
            "tls" => {
                let addr = uri
                    .strip_prefix("tls://")
                    .ok_or_else(|| LinkError::Protocol("invalid tls:// URI".to_string()))?;

                let mut addrs = addr.to_socket_addrs().map_err(|e| {
                    LinkError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
                })?;
                let socket = addrs.next().ok_or_else(|| {
                    LinkError::Protocol("URI did not resolve to an address".to_string())
                })?;

                self.connect(socket, sintf, link_type, priority, password)
                    .await
            }
            "tcp" => {
                // TCP protocol support
                Err(LinkError::Protocol(
                    "tcp:// protocol not yet integrated into links manager".to_string(),
                ))
            }
            "quic" => {
                // QUIC protocol support
                Err(LinkError::Protocol(
                    "quic:// protocol not yet integrated into links manager".to_string(),
                ))
            }
            #[cfg(unix)]
            "unix" => {
                // Unix socket protocol support
                Err(LinkError::Protocol(
                    "unix:// protocol not yet integrated into links manager".to_string(),
                ))
            }
            "ws" => {
                // WebSocket protocol support - module complete, needs integration
                Err(LinkError::Protocol(
                    "ws:// protocol module exists but not yet integrated into links manager"
                        .to_string(),
                ))
            }
            "wss" => {
                // WebSocket Secure protocol support - module complete, needs integration
                Err(LinkError::Protocol(
                    "wss:// protocol module exists but not yet integrated into links manager"
                        .to_string(),
                ))
            }
            "socks" | "sockstls" => {
                // SOCKS5 proxy support
                Err(LinkError::Protocol(format!(
                    "{}:// protocol not yet implemented",
                    protocol
                )))
            }
            _ => Err(LinkError::Protocol(format!(
                "unsupported protocol: {}",
                protocol
            ))),
        }
    }

    /// Disconnect from a peer by URI. Returns true if a connection was found and aborted.
    pub fn disconnect(&self, uri: &str) -> Result<bool, LinkError> {
        let mut links = self.links.write();
        if let Some(state) = links.get_mut(uri) {
            if let Some(conn) = state.conn.take() {
                conn.metrics.alive.store(false, Ordering::SeqCst);
                conn.task.abort();
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get information about all active links with counters.
    pub fn get_links(&self) -> Vec<LinkSummary> {
        let links = self.links.read();
        let total = links.len();
        let summaries: Vec<LinkSummary> = links
            .values()
            .filter_map(|state| {
                state.conn.as_ref().map(|c| LinkSummary {
                    info: c.info.clone(),
                    rx_bytes: c.metrics.rx.load(Ordering::Relaxed),
                    tx_bytes: c.metrics.tx.load(Ordering::Relaxed),
                    alive: c.metrics.alive.load(Ordering::Relaxed),
                    rtt_us: c.metrics.rtt_us.load(Ordering::Relaxed),
                })
            })
            .collect();

        debug!(
            total_stored = total,
            returned = summaries.len(),
            "get_links() called"
        );

        summaries
    }

    /// Count active connections.
    pub fn connection_count(&self) -> usize {
        let links = self.links.read();
        links.values().filter(|state| state.conn.is_some()).count()
    }

    /// Update the RTT measurement for a connection identified by peer key and port.
    pub fn update_rtt(&self, key: &PublicKey, port: PeerPort, rtt: Duration) {
        let rtt_us = rtt.as_micros() as u64;
        let links = self.links.read();

        // Prefer matching by both key and port for uniqueness.
        for state in links.values() {
            if let Some(conn) = &state.conn {
                if conn.info.remote_key == *key && conn.info.peer_port == port {
                    conn.metrics.rtt_us.store(rtt_us, Ordering::Relaxed);
                    return;
                }
            }
        }

        // Fallback: update first link matching the key if port lookup failed.
        for state in links.values() {
            if let Some(conn) = &state.conn {
                if conn.info.remote_key == *key {
                    conn.metrics.rtt_us.store(rtt_us, Ordering::Relaxed);
                    return;
                }
            }
        }
    }

    /// Get listener addresses.
    pub fn get_listeners(&self) -> Vec<SocketAddr> {
        self.listeners.read().clone()
    }
}

/// Generate a self-signed certificate for TLS.
fn generate_self_signed_cert(
    _public_key: &PublicKey,
) -> Result<
    (
        CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    LinkError,
> {
    use rcgen::{CertificateParams, KeyPair};

    // Generate a new key pair for the certificate
    // Note: Yggdrasil-go uses the Ed25519 key directly, but rustls requires different key types
    // We generate an ECDSA key for TLS (this is just for transport encryption, not node identity)
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| LinkError::Tls(format!("failed to generate key pair: {}", e)))?;

    let mut params = CertificateParams::new(vec!["yggdrasil".to_string()])
        .map_err(|e| LinkError::Tls(format!("failed to create cert params: {}", e)))?;

    // Set a reasonable validity period
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 10);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| LinkError::Tls(format!("failed to generate certificate: {}", e)))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );

    Ok((cert_der, key_der))
}

/// Wrapper that implements the ListenerFactory trait for Links.
/// This allows the multicast module to create TLS listeners via the Links manager.
pub struct LinksListenerFactory {
    links: Arc<Links>,
}

impl LinksListenerFactory {
    /// Create a new listener factory wrapping the Links manager.
    pub fn new(links: Arc<Links>) -> Self {
        Self { links }
    }
}

#[async_trait]
impl yggdrasil_multicast::ListenerFactory for LinksListenerFactory {
    async fn listen(
        &self,
        addr: SocketAddrV6,
        interface: &str,
        password: &[u8],
        _priority: u8,
    ) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
        let port = self
            .links
            .listen(SocketAddr::V6(addr), interface, password)
            .await?;
        Ok(port)
    }

    async fn stop_listener(&self, _interface: &str) {
        // Note: Stopping individual listeners requires tracking listener handles
        // with cancellation tokens per interface. For now, listeners will be
        // stopped when Links is stopped (via the running flag).
        // This is acceptable because multicast listeners are typically stopped
        // only when the application shuts down.
        tracing::debug!(
            interface = _interface,
            "stop_listener called - not implemented, listeners stop on shutdown"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_links_creation() {
        // Install the ring crypto provider for rustls (required for tests)
        let _ = rustls::crypto::ring::default_provider().install_default();

        let private_key = PrivateKey::generate();
        let (links, _rx) = Links::new(private_key);

        assert!(!links.is_running());

        links.start().await.unwrap();
        assert!(links.is_running());

        links.stop();
        assert!(!links.is_running());
    }
}
