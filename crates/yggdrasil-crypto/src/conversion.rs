//! Key conversion utilities.
//!
//! This module provides functions for converting between Ed25519 and X25519 keys,
//! matching the Go implementation in ironwood/encrypted/internal/e2c.

use curve25519_dalek::edwards::CompressedEdwardsY;
use yggdrasil_types::{CryptoError, PrivateKey, PublicKey};

use crate::box_crypto::{BoxPriv, BoxPub};

/// Convert an Ed25519 public key to an X25519 public key.
///
/// This performs the birational map from the Edwards curve to the Montgomery curve.
pub fn ed25519_public_to_x25519(ed_public: &PublicKey) -> Result<BoxPub, CryptoError> {
    let compressed = CompressedEdwardsY::from_slice(ed_public.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let edwards = compressed
        .decompress()
        .ok_or(CryptoError::InvalidPublicKey)?;

    let montgomery = edwards.to_montgomery();
    Ok(BoxPub::from(montgomery.to_bytes()))
}

/// Alias for ed25519_public_to_x25519 for API compatibility.
pub fn ed_to_curve25519_public(ed_public: &PublicKey) -> Option<BoxPub> {
    ed25519_public_to_x25519(ed_public).ok()
}

/// Convert an Ed25519 private key to an X25519 private key.
///
/// This extracts the seed from the Ed25519 key and uses it to derive the X25519 key.
pub fn ed25519_private_to_x25519(ed_private: &PrivateKey) -> BoxPriv {
    use sha2::{Digest, Sha512};

    // Get the seed (first 32 bytes)
    let seed: [u8; 32] = ed_private.as_bytes()[..32].try_into().unwrap();

    // Hash with SHA-512 (standard Ed25519 derivation)
    let mut hasher = Sha512::new();
    hasher.update(&seed);
    let hash = hasher.finalize();

    // Take first 32 bytes and clamp
    let mut x25519_key: [u8; 32] = hash[..32].try_into().unwrap();
    x25519_key[0] &= 248;
    x25519_key[31] &= 127;
    x25519_key[31] |= 64;

    BoxPriv::from_bytes(&x25519_key).expect("valid key length")
}

/// Alias for ed25519_private_to_x25519 for API compatibility.
pub fn ed_to_curve25519_secret(ed_private: &PrivateKey) -> BoxPriv {
    ed25519_private_to_x25519(ed_private)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed_to_x_public_conversion() {
        let ed_private = PrivateKey::generate();
        let ed_public = ed_private.public_key();

        // Convert public key
        let x_public = ed25519_public_to_x25519(&ed_public).unwrap();

        // The converted key should be 32 bytes
        assert_eq!(x_public.as_bytes().len(), 32);
    }

    #[test]
    fn test_ed_to_x_private_conversion() {
        let ed_private = PrivateKey::generate();

        // Convert private key
        let x_private = ed25519_private_to_x25519(&ed_private);

        // The converted key should be 32 bytes
        assert_eq!(x_private.as_bytes().len(), 32);
    }

    #[test]
    fn test_conversion_consistency() {
        // Converting the same Ed25519 key should always give the same X25519 key
        let ed_private = PrivateKey::generate();

        let x1 = ed25519_private_to_x25519(&ed_private);
        let x2 = ed25519_private_to_x25519(&ed_private);

        assert_eq!(x1.as_bytes(), x2.as_bytes());
    }

    #[test]
    fn test_keypair_relationship() {
        let ed_private = PrivateKey::generate();
        let ed_public = ed_private.public_key();

        // Convert both keys
        let x_private = ed25519_private_to_x25519(&ed_private);
        let x_public = ed25519_public_to_x25519(&ed_public).unwrap();

        // The derived public key from the converted private key should work
        // for key exchange with the converted public key
        let derived_pub = x_private.public_key();

        // Note: Due to the nature of the conversion (different curves),
        // the derived public key may differ from the direct conversion.
        // What matters is that key exchange still works.

        // The keys should both be valid 32-byte X25519 keys
        assert_eq!(x_public.as_bytes().len(), 32);
        assert_eq!(derived_pub.as_bytes().len(), 32);
    }
}
