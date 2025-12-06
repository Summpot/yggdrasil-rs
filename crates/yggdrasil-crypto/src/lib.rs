//! Cryptographic operations for the Yggdrasil network.
//!
//! This crate provides cryptographic primitives used by the Yggdrasil network,
//! including key exchange, encryption, and key conversion utilities.

pub mod box_crypto;
pub mod conversion;

pub use box_crypto::{
    BoxPriv as BoxSecretKey, BoxPub as BoxPublicKey, BoxShared as BoxSharedSecret, box_open,
    box_open_with_shared, box_seal, box_seal_with_shared, generate_box_keypair, generate_keypair,
    open_after_precomputation, precompute, seal_after_precomputation,
};
pub use conversion::*;

use yggdrasil_types::CryptoError;

/// Result type for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;
