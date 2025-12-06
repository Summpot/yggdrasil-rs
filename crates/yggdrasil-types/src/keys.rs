//! Cryptographic key types for the Yggdrasil network.
//!
//! This module provides wrappers around Ed25519 and X25519 keys with
//! utility methods matching the Go implementation.

use std::fmt;

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::error::CryptoError;
use crate::sizes::*;

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Create a public key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of the public key.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert to a VerifyingKey for signature verification.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Verify a signature on a message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        match self.to_verifying_key() {
            Ok(vk) => {
                let sig = match DalekSignature::from_bytes(&signature.0) {
                    sig => sig,
                };
                vk.verify(message, &sig).is_ok()
            }
            Err(_) => false,
        }
    }

    /// Check if this key is less than another key (lexicographic comparison).
    /// Used for deterministic ordering in the routing protocol.
    pub fn less(&self, other: &Self) -> bool {
        for i in 0..PUBLIC_KEY_SIZE {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        false
    }

    /// Convert to a network address representation.
    pub fn to_addr(&self) -> Addr {
        Addr(self.0)
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        Self([0u8; PUBLIC_KEY_SIZE])
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// An Ed25519 private key (includes the public key component).
#[derive(Clone)]
pub struct PrivateKey([u8; PRIVATE_KEY_SIZE]);

impl PrivateKey {
    /// Generate a new random private key.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self(signing_key.to_keypair_bytes())
    }

    /// Create a private key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PRIVATE_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PRIVATE_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of the private key.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_SIZE] {
        &self.0
    }

    /// Get the public key corresponding to this private key.
    pub fn public_key(&self) -> PublicKey {
        let mut pub_bytes = [0u8; PUBLIC_KEY_SIZE];
        pub_bytes.copy_from_slice(&self.0[32..]);
        PublicKey(pub_bytes)
    }

    /// Convert to a SigningKey for signing operations.
    pub fn to_signing_key(&self) -> Result<SigningKey, CryptoError> {
        // The first 32 bytes are the seed, the last 32 bytes are the public key
        let seed: [u8; 32] = self.0[..32].try_into().unwrap();
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Sign a message with this private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let signing_key = self.to_signing_key().expect("valid signing key");
        let sig = signing_key.sign(message);
        Signature(sig.to_bytes())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for private keys
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for PrivateKey {}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::generate()
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

// Ensure private key is zeroized on drop
impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zero out the key bytes
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Create a signature from raw bytes.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Try to create a signature from a byte slice.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of the signature.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Convert to a raw byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; SIGNATURE_SIZE])
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SIGNATURE_SIZE]> for Signature {
    fn from(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0))
    }
}

/// A network address derived from an Ed25519 public key.
/// Implements the `net.Addr` interface semantics from Go.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Addr([u8; PUBLIC_KEY_SIZE]);

impl Addr {
    /// Create an address from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of the address.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert to a PublicKey.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0)
    }

    /// Returns the network type identifier (matches Go's net.Addr interface).
    pub fn network(&self) -> &'static str {
        "ed25519.PublicKey"
    }
}

impl Default for Addr {
    fn default() -> Self {
        Self([0u8; PUBLIC_KEY_SIZE])
    }
}

impl AsRef<[u8]> for Addr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for Addr {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for Addr {
    fn from(key: PublicKey) -> Self {
        Self(key.0)
    }
}

impl TryFrom<&[u8]> for Addr {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Addr({})", hex::encode(self.0))
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// Need subtle crate for constant-time comparison
mod subtle {
    pub trait ConstantTimeEq {
        fn ct_eq(&self, other: &Self) -> Choice;
    }

    #[derive(Clone, Copy)]
    pub struct Choice(u8);

    impl From<Choice> for bool {
        fn from(c: Choice) -> bool {
            c.0 == 1
        }
    }

    impl ConstantTimeEq for [u8; 64] {
        fn ct_eq(&self, other: &Self) -> Choice {
            let mut result = 0u8;
            for (a, b) in self.iter().zip(other.iter()) {
                result |= a ^ b;
            }
            // If result is 0, all bytes matched
            // Use i16 to avoid overflow when shifting
            Choice((((result as i16) - 1) >> 8) as u8 & 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        // Verify the public key is derived correctly
        let signing_key = private.to_signing_key().unwrap();
        let expected_public = signing_key.verifying_key().to_bytes();
        assert_eq!(public.as_bytes(), &expected_public);
    }

    #[test]
    fn test_sign_verify() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let message = b"Hello, Yggdrasil!";
        let signature = private.sign(message);

        assert!(public.verify(message, &signature));

        // Verify that wrong message fails
        assert!(!public.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_public_key_ordering() {
        let key1 = PublicKey::from([0u8; 32]);
        let key2 = PublicKey::from([1u8; 32]);

        assert!(key1.less(&key2));
        assert!(!key2.less(&key1));
        assert!(!key1.less(&key1));
    }

    #[test]
    fn test_addr_conversion() {
        let private = PrivateKey::generate();
        let public = private.public_key();
        let addr = public.to_addr();

        assert_eq!(addr.as_bytes(), public.as_bytes());
        assert_eq!(addr.to_public_key(), public);
        assert_eq!(addr.network(), "ed25519.PublicKey");
    }
}
