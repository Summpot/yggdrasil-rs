//! TUN interface for the Yggdrasil network.
//!
//! This crate provides TUN interface management for the Yggdrasil network,
//! allowing it to create a virtual network interface for routing IPv6 traffic.

mod tun;
#[cfg(windows)]
mod wintun_dll;

pub use tun::{TunAdapter, TunConfig, TunError};
