//! Yggdrasil core library
//!
//! Provides core implementation of the Yggdrasil network protocol

#![forbid(unsafe_code)]

pub mod address;
pub mod admin;
pub mod admin_compat;
pub mod config;
pub mod core;
pub mod crypto;
pub mod handshake;
pub mod link;
pub mod lookup;
pub mod metrics;
pub mod multicast;
pub mod nodeinfo;
pub mod peer;
pub mod proto;
pub mod quic_pool;
pub mod router;
pub mod session;
pub mod spanning_tree;
pub mod tun_adapter;

// Re-export commonly used types
pub use address::{Address, Subnet};
pub use admin::{AdminClient, AdminServer};
pub use config::{Config, ConfigFormat, MulticastInterfaceConfig};
pub use core::Core;
pub use crypto::Crypto;
pub use lookup::{BloomFilter, LookupManager, LookupStats};
pub use metrics::{MetricsRegistry, YggdrasilMetrics};
pub use quic_pool::{QuicPool, QuicPoolConfig, QuicPoolStats};
pub use spanning_tree::{SpanningTree, TreeAnnouncement};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
