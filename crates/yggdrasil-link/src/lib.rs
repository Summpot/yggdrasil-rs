//! Link layer for the Yggdrasil network.
//!
//! This crate provides link layer abstractions for various transport protocols.

pub mod handshake;
pub mod link;
pub mod links;
pub mod peer_handler;
pub mod quic;
pub mod tcp;
pub mod tls;
#[cfg(unix)]
pub mod unix;
pub mod websocket;

pub use handshake::{HandshakeError, VersionMetadata, perform_handshake};
pub use link::{Link, LinkConfig, LinkError, LinkInfo as BasicLinkInfo};
pub use links::{LinkInfo, LinkSummary, LinkType, Links, LinksListenerFactory, PeerConnectedEvent};
pub use peer_handler::{OutgoingPacket, PeerEvent, PeerHandler, create_peer_channels};
pub use quic::{QuicConfig, QuicLink, create_client_endpoint, create_server_endpoint};
pub use tcp::TcpLink;
pub use tls::{TlsClientLink, TlsServerLink, create_insecure_client_config, create_server_config};
#[cfg(unix)]
pub use unix::UnixLink;
pub use websocket::WebSocketLink;
