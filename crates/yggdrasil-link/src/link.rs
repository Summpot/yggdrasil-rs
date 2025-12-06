//! Core link types and traits.

use std::net::SocketAddr;
use std::time::Instant;

use async_trait::async_trait;
use yggdrasil_types::PublicKey;

/// Link configuration.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Whether to use TLS.
    pub use_tls: bool,
    /// Connection timeout.
    pub timeout: std::time::Duration,
    /// Maximum message size.
    pub max_message_size: usize,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            use_tls: true,
            timeout: std::time::Duration::from_secs(30),
            max_message_size: 65535,
        }
    }
}

/// Information about a link.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    /// Remote public key.
    pub remote_key: PublicKey,
    /// Remote address.
    pub remote_addr: SocketAddr,
    /// Local address.
    pub local_addr: SocketAddr,
    /// Link type (tcp, tls, quic, etc.).
    pub link_type: String,
    /// Whether this is an outbound link.
    pub outbound: bool,
    /// Time when the link was established.
    pub established: Instant,
}

/// A network link to a peer.
#[async_trait]
pub trait Link: Send + Sync {
    /// Get the link information.
    fn info(&self) -> &LinkInfo;

    /// Send a message through the link.
    async fn send(&self, data: &[u8]) -> Result<(), LinkError>;

    /// Receive a message from the link.
    async fn recv(&self) -> Result<Vec<u8>, LinkError>;

    /// Close the link.
    async fn close(&self) -> Result<(), LinkError>;

    /// Check if the link is still connected.
    fn is_connected(&self) -> bool;
}

/// Errors that can occur with links.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("connection closed")]
    Closed,
    #[error("connection timeout")]
    Timeout,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("TLS error: {0}")]
    Tls(String),
}
