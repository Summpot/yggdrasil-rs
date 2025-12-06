//! Multicast peer discovery for the Yggdrasil network.
//!
//! This module implements the multicast beacon-based peer discovery mechanism
//! used by Yggdrasil to automatically discover and connect to peers on the
//! same local network segment.

mod advertisement;
mod config;
mod multicast;

pub use advertisement::MulticastAdvertisement;
pub use config::{MulticastConfig, MulticastInterfaceConfig};
pub use multicast::{
    ListenerFactory, Multicast, MulticastError, MulticastInterface, PeerDiscoveredEvent,
};
