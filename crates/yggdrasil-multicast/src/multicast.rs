//! Multicast peer discovery implementation.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use blake2::{Blake2b512, Digest};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use parking_lot::RwLock;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use yggdrasil_types::PublicKey;

use crate::advertisement::{
    MulticastAdvertisement, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
};
use crate::config::MulticastConfig;

/// Trait for creating TLS listeners.
/// This allows the multicast module to create listeners without depending on yggdrasil-link.
#[async_trait]
pub trait ListenerFactory: Send + Sync {
    /// Create a TLS listener on the given address.
    /// Returns the actual port that was bound (may differ if port was 0).
    async fn listen(
        &self,
        addr: SocketAddrV6,
        interface: &str,
        password: &[u8],
        priority: u8,
    ) -> Result<u16, Box<dyn std::error::Error + Send + Sync>>;

    /// Stop the listener on the given interface.
    async fn stop_listener(&self, interface: &str);
}

/// Default multicast group address for Yggdrasil.
#[allow(dead_code)]
pub const DEFAULT_GROUP_ADDR: &str = "[ff02::114]:9001";

/// Errors that can occur during multicast operations.
#[derive(Debug, thiserror::Error)]
pub enum MulticastError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Multicast already started")]
    AlreadyStarted,
    #[error("Failed to resolve address: {0}")]
    AddressResolve(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Information about a discovered interface.
#[derive(Debug, Clone)]
pub struct MulticastInterface {
    /// Interface name.
    pub name: String,
    /// Interface index.
    pub index: u32,
    /// Link-local IPv6 addresses on this interface.
    pub addrs: Vec<Ipv6Addr>,
    /// Whether to send beacons on this interface.
    pub beacon: bool,
    /// Whether to listen for beacons on this interface.
    pub listen: bool,
    /// Port for the TLS listener.
    pub port: u16,
    /// Priority for this interface.
    pub priority: u8,
    /// Password for multicast peers.
    pub password: Vec<u8>,
    /// BLAKE2b hash for password verification.
    pub hash: Vec<u8>,
}

/// Event emitted when a peer is discovered via multicast.
#[derive(Debug, Clone)]
pub struct PeerDiscoveredEvent {
    /// The discovered peer's public key.
    pub public_key: PublicKey,
    /// The address to connect to.
    pub addr: SocketAddr,
    /// The interface on which the peer was discovered.
    pub interface: String,
    /// Priority of the interface.
    pub priority: u8,
    /// Password for the connection (if any).
    pub password: String,
}

/// Information about a listener on an interface.
struct ListenerInfo {
    /// Last announcement time.
    last_announce: Instant,
    /// Announcement interval.
    interval: Duration,
    /// The port we're listening on.
    port: u16,
    /// The link-local address we're listening on.
    addr: Ipv6Addr,
}

/// Multicast peer discovery module.
pub struct Multicast {
    /// Our public key.
    public_key: PublicKey,
    /// Configuration.
    config: MulticastConfig,
    /// Running state.
    running: AtomicBool,
    /// Known interfaces.
    interfaces: RwLock<HashMap<String, MulticastInterface>>,
    /// Listener info per interface.
    listeners: RwLock<HashMap<String, ListenerInfo>>,
    /// Channel for discovered peers.
    peer_tx: mpsc::UnboundedSender<PeerDiscoveredEvent>,
    /// Factory for creating TLS listeners.
    listener_factory: RwLock<Option<Arc<dyn ListenerFactory>>>,
}

impl Multicast {
    /// Create a new multicast module.
    pub fn new(
        public_key: PublicKey,
        config: MulticastConfig,
    ) -> (Self, mpsc::UnboundedReceiver<PeerDiscoveredEvent>) {
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();

        (
            Self {
                public_key,
                config,
                running: AtomicBool::new(false),
                interfaces: RwLock::new(HashMap::new()),
                listeners: RwLock::new(HashMap::new()),
                peer_tx,
                listener_factory: RwLock::new(None),
            },
            peer_rx,
        )
    }

    /// Set the listener factory for creating TLS listeners.
    pub fn set_listener_factory(&self, factory: Arc<dyn ListenerFactory>) {
        *self.listener_factory.write() = Some(factory);
    }

    /// Start the multicast module.
    pub async fn start(self: Arc<Self>) -> Result<(), MulticastError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(MulticastError::AlreadyStarted);
        }

        // Check if any interfaces are enabled
        let any_enabled = self.config.interfaces.iter().any(|i| i.beacon || i.listen);

        if !any_enabled {
            self.running.store(false, Ordering::SeqCst);
            info!("No multicast interfaces enabled, not starting multicast module");
            return Ok(());
        }

        info!("Starting multicast module");

        // Parse the group address
        let group_addr: SocketAddrV6 = self
            .config
            .group_addr
            .parse()
            .map_err(|e| MulticastError::AddressResolve(format!("{}", e)))?;

        // Create the socket
        let socket = self.create_socket(group_addr.port())?;
        let socket = Arc::new(UdpSocket::from_std(socket.into())?);

        // Start the listener task
        let self_clone = self.clone();
        let socket_clone = socket.clone();
        let group_addr_clone = group_addr;
        tokio::spawn(async move {
            self_clone.listen_loop(socket_clone, group_addr_clone).await;
        });

        // Start the announcement task
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.announce_loop(socket, group_addr).await;
        });

        Ok(())
    }

    /// Stop the multicast module.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Stopped multicast module");
    }

    /// Check if the module is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the current interfaces.
    pub fn interfaces(&self) -> HashMap<String, MulticastInterface> {
        self.interfaces.read().clone()
    }

    /// Create the UDP socket for multicast.
    fn create_socket(&self, port: u16) -> Result<Socket, MulticastError> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

        // Set socket options
        socket.set_reuse_address(true)?;

        #[cfg(unix)]
        {
            // On Unix, we use SO_REUSEADDR
            use socket2::SockAddr;
            let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
            socket.bind(&SockAddr::from(addr))?;
        }

        #[cfg(windows)]
        {
            // On Windows, set SO_REUSEADDR before binding
            use socket2::SockAddr;
            let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
            socket.bind(&SockAddr::from(addr))?;
        }

        socket.set_nonblocking(true)?;

        Ok(socket)
    }

    /// Update the list of allowed interfaces.
    fn update_interfaces(&self) {
        let mut new_interfaces = HashMap::new();

        // Get all network interfaces
        let interfaces = match NetworkInterface::show() {
            Ok(ifaces) => ifaces,
            Err(e) => {
                warn!("Failed to get network interfaces: {}", e);
                return;
            }
        };

        for iface in interfaces {
            // Skip loopback interfaces
            if iface.name.starts_with("lo") {
                continue;
            }

            // Check if any config matches this interface
            for cfg in &self.config.interfaces {
                if !cfg.beacon && !cfg.listen {
                    continue;
                }

                if !cfg.regex.is_match(&iface.name) {
                    continue;
                }

                // Get link-local IPv6 addresses
                let mut link_local_addrs = Vec::new();
                for addr in &iface.addr {
                    if let Addr::V6(v6_addr) = addr {
                        let ip = v6_addr.ip;
                        // Check if it's link-local (fe80::/10)
                        let octets = ip.octets();
                        if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                            link_local_addrs.push(ip);
                        }
                    }
                }

                if link_local_addrs.is_empty() {
                    continue;
                }

                // Compute BLAKE2b hash for password verification
                let hash = {
                    let mut hasher = Blake2b512::new();
                    hasher.update(cfg.password.as_bytes());
                    hasher.update(self.public_key.as_bytes());
                    hasher.finalize().to_vec()
                };

                let info = MulticastInterface {
                    name: iface.name.clone(),
                    index: iface.index,
                    addrs: link_local_addrs,
                    beacon: cfg.beacon,
                    listen: cfg.listen,
                    port: cfg.port,
                    priority: cfg.priority,
                    password: cfg.password.as_bytes().to_vec(),
                    hash,
                };

                debug!(
                    "Discovered multicast interface: {} ({} addresses)",
                    iface.name,
                    info.addrs.len()
                );
                new_interfaces.insert(iface.name.clone(), info);
                break; // Only use first matching config
            }
        }

        *self.interfaces.write() = new_interfaces;
    }

    /// Listen for multicast beacons.
    async fn listen_loop(self: Arc<Self>, socket: Arc<UdpSocket>, group_addr: SocketAddrV6) {
        let mut buf = [0u8; 2048];

        while self.is_running() {
            // Update interfaces periodically
            self.update_interfaces();

            // Join multicast groups on all interfaces that have listen enabled
            for (name, info) in self.interfaces.read().iter() {
                if info.listen {
                    // Join the multicast group on this interface
                    // Note: This is done on each iteration to handle interface changes
                    if let Err(e) = socket.join_multicast_v6(group_addr.ip(), info.index) {
                        trace!("Failed to join multicast on {}: {}", name, e);
                    }
                }
            }

            // Wait for incoming packets with timeout
            let recv_result =
                tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await;

            match recv_result {
                Ok(Ok((n, from))) => {
                    self.handle_beacon(&buf[..n], from).await;
                }
                Ok(Err(e)) => {
                    trace!("Receive error: {}", e);
                }
                Err(_) => {
                    // Timeout, continue
                }
            }
        }
    }

    /// Handle a received multicast beacon.
    async fn handle_beacon(&self, data: &[u8], from: SocketAddr) {
        let adv = match MulticastAdvertisement::from_bytes(data) {
            Ok(adv) => adv,
            Err(e) => {
                trace!("Failed to parse multicast beacon: {}", e);
                return;
            }
        };

        // Check protocol version
        if adv.major_version != PROTOCOL_VERSION_MAJOR {
            trace!(
                "Protocol version mismatch: {} != {}",
                adv.major_version, PROTOCOL_VERSION_MAJOR
            );
            return;
        }
        if adv.minor_version != PROTOCOL_VERSION_MINOR {
            trace!(
                "Protocol minor version mismatch: {} != {}",
                adv.minor_version, PROTOCOL_VERSION_MINOR
            );
            return;
        }

        // Check if this is our own beacon
        if adv.public_key == *self.public_key.as_bytes() {
            return;
        }

        // Get the interface this came from
        let from_v6 = match from {
            SocketAddr::V6(v6) => v6,
            _ => return,
        };

        let scope_id = from_v6.scope_id();
        let interfaces = self.interfaces.read();

        // Find the interface by scope_id
        let interface = interfaces
            .values()
            .find(|i| i.index == scope_id && i.listen);

        let interface = match interface {
            Some(i) => i,
            None => {
                trace!("Received beacon from unknown interface scope {}", scope_id);
                return;
            }
        };

        // Verify the password hash
        let expected_hash = {
            let mut hasher = Blake2b512::new();
            hasher.update(&interface.password);
            hasher.update(&adv.public_key);
            hasher.finalize().to_vec()
        };

        if adv.hash != expected_hash {
            trace!("Password hash mismatch for peer");
            return;
        }

        // Create the peer address
        let peer_addr = SocketAddrV6::new(*from_v6.ip(), adv.port, 0, scope_id);

        // Parse public key
        let public_key = match PublicKey::from_bytes(&adv.public_key) {
            Ok(pk) => pk,
            Err(e) => {
                trace!("Invalid public key in beacon: {:?}", e);
                return;
            }
        };

        debug!(
            "Discovered peer via multicast: {} on {}",
            hex::encode(&adv.public_key[..8]),
            interface.name
        );

        // Emit the peer discovered event
        let event = PeerDiscoveredEvent {
            public_key,
            addr: SocketAddr::V6(peer_addr),
            interface: interface.name.clone(),
            priority: interface.priority,
            password: String::from_utf8_lossy(&interface.password).to_string(),
        };

        if let Err(e) = self.peer_tx.send(event) {
            trace!("Failed to send peer discovered event: {}", e);
        }
    }

    /// Announce our presence via multicast beacons.
    async fn announce_loop(self: Arc<Self>, socket: Arc<UdpSocket>, group_addr: SocketAddrV6) {
        use rand::Rng;

        while self.is_running() {
            self.update_interfaces();

            // First, clean up listeners for interfaces that are no longer valid
            {
                let interfaces = self.interfaces.read();
                let mut listeners = self.listeners.write();
                let factory = self.listener_factory.read().clone();

                // Remove listeners for interfaces that are no longer available or have changed addresses
                let to_remove: Vec<String> = listeners
                    .iter()
                    .filter(|(name, info)| {
                        match interfaces.get(*name) {
                            None => true, // Interface gone
                            Some(iface) => {
                                // Check if the listener address is still valid
                                !iface.addrs.contains(&info.addr)
                            }
                        }
                    })
                    .map(|(name, _)| name.clone())
                    .collect();

                for name in to_remove {
                    debug!(
                        "Stopping multicast listener on {} (interface changed)",
                        name
                    );
                    listeners.remove(&name);
                    // Stop the listener in the factory
                    if let Some(ref factory) = factory {
                        let factory = factory.clone();
                        let name = name.clone();
                        tokio::spawn(async move {
                            factory.stop_listener(&name).await;
                        });
                    }
                }
            }

            // Collect interfaces that need listeners created or beacons sent
            let work_items: Vec<_> = {
                let interfaces = self.interfaces.read();
                let listeners = self.listeners.read();

                interfaces
                    .iter()
                    .filter(|(_, info)| info.beacon)
                    .filter_map(|(name, info)| {
                        // Get the first link-local address
                        let addr = info.addrs.first()?;

                        // Check if we already have a listener
                        let listener_info = listeners.get(name);

                        Some((
                            name.clone(),
                            *addr,
                            info.index,
                            info.port,
                            info.priority,
                            info.password.clone(),
                            info.hash.clone(),
                            listener_info.map(|l| (l.port, l.last_announce, l.interval)),
                        ))
                    })
                    .collect()
            };

            // Process each interface
            for (name, addr, index, config_port, priority, password, hash, listener_state) in
                work_items
            {
                let port = match listener_state {
                    Some((port, last_announce, interval)) => {
                        // Already have a listener, check if we should announce
                        if last_announce.elapsed() < interval {
                            continue;
                        }
                        port
                    }
                    None => {
                        // Need to create a listener
                        let factory = self.listener_factory.read().clone();
                        if factory.is_none() {
                            trace!(
                                "No listener factory set, skipping {} (cannot create listener)",
                                name
                            );
                            continue;
                        }
                        let factory = factory.unwrap();

                        let listen_addr = SocketAddrV6::new(addr, config_port, 0, index);
                        match factory
                            .listen(listen_addr, &name, &password, priority)
                            .await
                        {
                            Ok(actual_port) => {
                                debug!(
                                    "Started TLS listener on {} at [{:#}]:{}",
                                    name, addr, actual_port
                                );
                                // Store the listener info
                                let mut listeners = self.listeners.write();
                                listeners.insert(
                                    name.clone(),
                                    ListenerInfo {
                                        last_announce: Instant::now() - Duration::from_secs(10),
                                        interval: Duration::from_secs(1),
                                        port: actual_port,
                                        addr,
                                    },
                                );
                                actual_port
                            }
                            Err(e) => {
                                warn!("Failed to start TLS listener on {}: {}", name, e);
                                continue;
                            }
                        }
                    }
                };

                // Create and send the advertisement
                let adv = MulticastAdvertisement::new(&self.public_key, port, hash.clone());

                let bytes = adv.to_bytes();
                let dest = SocketAddrV6::new(*group_addr.ip(), group_addr.port(), 0, index);

                if let Err(e) = socket.send_to(&bytes, SocketAddr::V6(dest)).await {
                    trace!("Failed to send multicast beacon on {}: {}", name, e);
                } else {
                    trace!(
                        "Sent multicast beacon on {} via {} port {}",
                        name, addr, port
                    );
                }

                // Update timing
                let mut listeners = self.listeners.write();
                if let Some(info) = listeners.get_mut(&name) {
                    info.last_announce = Instant::now();
                    if info.interval < Duration::from_secs(15) {
                        info.interval += Duration::from_secs(1);
                    }
                }
            }

            // Randomized delay between announcements
            let delay = Duration::from_millis(1000 + rand::rng().random_range(0..1048));
            tokio::time::sleep(delay).await;
        }
    }
}

impl Drop for Multicast {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicast_config() {
        let config = MulticastConfig::default();
        assert!(!config.interfaces.is_empty());
        assert_eq!(config.group_addr, "[ff02::114]:9001");
    }
}
