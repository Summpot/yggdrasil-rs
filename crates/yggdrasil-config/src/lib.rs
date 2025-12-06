//! Configuration for the Yggdrasil network.
//!
//! This crate provides configuration structures and parsing for Yggdrasil nodes.

mod config;
mod defaults;

pub use config::{MulticastInterfaceConfig, NodeConfig};
pub use defaults::{Defaults, get_defaults};
