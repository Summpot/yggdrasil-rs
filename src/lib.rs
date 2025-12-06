//! Core functionality for the Yggdrasil network.
//!
//! This crate provides the main `Core` struct that coordinates all Yggdrasil
//! functionality including routing, session management, and link handling.

pub mod admin;
pub mod admin_server;
mod core;
mod version;

pub use crate::core::{Core, CoreConfig, CoreError};
pub use admin_server::{AdminServer, AdminServerError};
pub use version::VERSION;

// Re-export commonly used types from other crates
pub use yggdrasil_address::{Address, Subnet};
pub use yggdrasil_config::NodeConfig;
pub use yggdrasil_types::{PrivateKey, PublicKey};
