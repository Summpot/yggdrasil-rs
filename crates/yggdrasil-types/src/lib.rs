//! Core types for the Yggdrasil network.
//!
//! This crate provides the fundamental types used throughout the Yggdrasil network
//! implementation, including cryptographic key types, addresses, and error types.

mod error;
mod keys;

pub use error::*;
pub use keys::*;

/// Type alias for secret key (same as PrivateKey, for API compatibility).
pub type SecretKey = PrivateKey;

/// Size constants matching the Go implementation
pub mod sizes {
    /// Size of an Ed25519 public key in bytes
    pub const PUBLIC_KEY_SIZE: usize = 32;
    /// Size of an Ed25519 private key in bytes
    pub const PRIVATE_KEY_SIZE: usize = 64;
    /// Size of an Ed25519 signature in bytes
    pub const SIGNATURE_SIZE: usize = 64;
    /// Size of an X25519 public key in bytes
    pub const BOX_PUBLIC_KEY_SIZE: usize = 32;
    /// Size of an X25519 private key in bytes
    pub const BOX_PRIVATE_KEY_SIZE: usize = 32;
    /// Size of an X25519 shared secret in bytes
    pub const BOX_SHARED_SIZE: usize = 32;
    /// Size of a NaCl box nonce in bytes
    pub const BOX_NONCE_SIZE: usize = 24;
    /// Overhead of NaCl box encryption in bytes
    pub const BOX_OVERHEAD: usize = 16;
}

/// Peer port type used in routing
pub type PeerPort = u64;
