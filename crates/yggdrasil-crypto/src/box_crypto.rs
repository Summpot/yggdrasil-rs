//! NaCl box-style encryption using X25519 and XSalsa20-Poly1305.
//!
//! This module provides functions for encrypting and decrypting messages
//! using the NaCl box construction, matching the Go implementation.

use crypto_box::{
    SalsaBox, Nonce, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey,
    aead::{Aead, OsRng},
};

use yggdrasil_types::{CryptoError, sizes::*};

/// An X25519 public key for box encryption.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoxPub([u8; BOX_PUBLIC_KEY_SIZE]);

impl BoxPub {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != BOX_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: BOX_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; BOX_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Create from a slice, returning None if invalid.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes).ok()
    }

    /// Get the raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; BOX_PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert to crypto_box PublicKey.
    pub fn to_box_public_key(&self) -> BoxPublicKey {
        BoxPublicKey::from(self.0)
    }
}

impl Default for BoxPub {
    fn default() -> Self {
        Self([0u8; BOX_PUBLIC_KEY_SIZE])
    }
}

impl From<[u8; BOX_PUBLIC_KEY_SIZE]> for BoxPub {
    fn from(bytes: [u8; BOX_PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for BoxPub {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for BoxPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoxPub({})", hex::encode(self.0))
    }
}

/// An X25519 private key for box encryption.
#[derive(Clone)]
pub struct BoxPriv([u8; BOX_PRIVATE_KEY_SIZE]);

impl BoxPriv {
    /// Generate a new random private key.
    pub fn generate() -> Self {
        let secret = BoxSecretKey::generate(&mut OsRng);
        Self(secret.to_bytes())
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != BOX_PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: BOX_PRIVATE_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; BOX_PRIVATE_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; BOX_PRIVATE_KEY_SIZE] {
        &self.0
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> BoxPub {
        let secret = BoxSecretKey::from(self.0);
        BoxPub(secret.public_key().to_bytes())
    }

    /// Convert to crypto_box SecretKey.
    pub fn to_box_secret_key(&self) -> BoxSecretKey {
        BoxSecretKey::from(self.0)
    }
}

impl PartialEq for BoxPriv {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison
        let mut result = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Eq for BoxPriv {}

impl Drop for BoxPriv {
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

impl std::fmt::Debug for BoxPriv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoxPriv([REDACTED])")
    }
}

/// A precomputed shared secret for box encryption.
#[derive(Clone)]
pub struct BoxShared([u8; BOX_SHARED_SIZE]);

impl Default for BoxShared {
    fn default() -> Self {
        Self([0u8; BOX_SHARED_SIZE])
    }
}

impl BoxShared {
    /// Compute the shared secret between a public and private key.
    /// This matches the NaCl box precompute: X25519 DH followed by HSalsa20.
    ///
    /// Corresponds to crypto_box_beforenm in NaCl spec:
    /// https://nacl.cr.yp.to/box.html
    pub fn new(their_public: &BoxPub, my_private: &BoxPriv) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::from(my_private.0);
        let public = PublicKey::from(their_public.0);
        let dh_result = secret.diffie_hellman(&public);

        // Apply HSalsa20 to the DH result, matching NaCl's Precompute
        // Go: box.Precompute calls: curve25519.ScalarMult followed by salsa.HSalsa20
        // See: https://github.com/golang/crypto/blob/main/nacl/box/box.go#L79-L81
        //   curve25519.ScalarMult(sharedKey, privateKey, peersPublicKey)
        //   salsa.HSalsa20(sharedKey, &zeros, sharedKey, &salsa.Sigma)
        //
        // NaCl box uses crypto_core_hsalsa20(sharedkey, zero, sharedkey, sigma)
        // where sigma = "expand 32-byte k"
        use salsa20::hsalsa;
        const SIGMA: [u8; 16] = *b"expand 32-byte k";
        const ZERO: [u8; 16] = [0u8; 16];
        
        use generic_array::GenericArray;
        let key = GenericArray::from_slice(dh_result.as_bytes());
        let input = GenericArray::from_slice(&ZERO);
        
        // HSalsa20 uses 10 rounds (U10), matching Salsa20/20
        // Each "round" in the generic parameter means one full round (column + diagonal)
        let shared_result = hsalsa::<typenum::consts::U10>(key, input);

        Self(*shared_result.as_ref())
    }

    /// Get the raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; BOX_SHARED_SIZE] {
        &self.0
    }
}

impl Drop for BoxShared {
    fn drop(&mut self) {
        // Zero out the shared secret
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl std::fmt::Debug for BoxShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoxShared([REDACTED])")
    }
}

/// Generate a new key pair.
pub fn generate_box_keypair() -> (BoxPub, BoxPriv) {
    let priv_key = BoxPriv::generate();
    let pub_key = priv_key.public_key();
    (pub_key, priv_key)
}

/// Alias for generate_box_keypair for compatibility.
pub fn generate_keypair() -> (BoxPub, BoxPriv) {
    generate_box_keypair()
}

/// Compute shared secret (precompute).
pub fn precompute(their_public: &BoxPub, my_private: &BoxPriv) -> BoxShared {
    BoxShared::new(their_public, my_private)
}

/// Seal (encrypt) using a precomputed shared secret.
pub fn seal_after_precomputation(msg: &[u8], nonce: u64, shared: &BoxShared) -> Vec<u8> {
    box_seal_with_shared(msg, nonce, shared)
}

/// Open (decrypt) using a precomputed shared secret.
pub fn open_after_precomputation(
    ciphertext: &[u8],
    nonce: u64,
    shared: &BoxShared,
) -> Option<Vec<u8>> {
    box_open_with_shared(ciphertext, nonce, shared).ok()
}

/// Create a nonce from a u64 value.
/// The nonce is 24 bytes with the u64 in the last 8 bytes (big-endian).
fn nonce_for_u64(value: u64) -> [u8; BOX_NONCE_SIZE] {
    let mut nonce = [0u8; BOX_NONCE_SIZE];
    nonce[BOX_NONCE_SIZE - 8..].copy_from_slice(&value.to_be_bytes());
    nonce
}

/// Encrypt a message using precomputed shared secret.
/// Uses a u64 nonce that is converted to a 24-byte nonce.
pub fn box_seal(
    msg: &[u8],
    nonce: u64,
    their_public: &BoxPub,
    my_private: &BoxPriv,
) -> Result<Vec<u8>, CryptoError> {
    let their_pk = their_public.to_box_public_key();
    let my_sk = my_private.to_box_secret_key();
    let the_box = SalsaBox::new(&their_pk, &my_sk);

    let nonce_bytes = nonce_for_u64(nonce);
    let nonce = Nonce::from_slice(&nonce_bytes);

    the_box
        .encrypt(nonce, msg)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Decrypt a message using precomputed shared secret.
/// Uses a u64 nonce that is converted to a 24-byte nonce.
pub fn box_open(
    ciphertext: &[u8],
    nonce: u64,
    their_public: &BoxPub,
    my_private: &BoxPriv,
) -> Result<Vec<u8>, CryptoError> {
    let their_pk = their_public.to_box_public_key();
    let my_sk = my_private.to_box_secret_key();
    let the_box = SalsaBox::new(&their_pk, &my_sk);

    let nonce_bytes = nonce_for_u64(nonce);
    let nonce = Nonce::from_slice(&nonce_bytes);

    the_box
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt a message using precomputed shared secret.
pub fn box_seal_with_shared(msg: &[u8], nonce: u64, shared: &BoxShared) -> Vec<u8> {
    // For shared secret encryption, we need to use a different approach
    // since crypto_box doesn't directly support precomputed secrets
    // We'll use XSalsa20-Poly1305 directly with the shared secret

    use crypto_box::aead::KeyInit;

    // Use XSalsa20Poly1305 with the shared secret as key
    use xsalsa20poly1305::{XSalsa20Poly1305, Key};

    let key = Key::from_slice(shared.as_bytes());
    let cipher = XSalsa20Poly1305::new(key);

    // Use full 24-byte nonce for XSalsa20
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce = xsalsa20poly1305::Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(nonce, msg)
        .expect("encryption should not fail")
}

/// Decrypt a message using precomputed shared secret.
pub fn box_open_with_shared(
    ciphertext: &[u8],
    nonce: u64,
    shared: &BoxShared,
) -> Result<Vec<u8>, CryptoError> {
    use xsalsa20poly1305::{XSalsa20Poly1305, Key};
    use crypto_box::aead::KeyInit;

    let key = Key::from_slice(shared.as_bytes());
    let cipher = XSalsa20Poly1305::new(key);

    // Use full 24-byte nonce for XSalsa20
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce = xsalsa20poly1305::Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (pub_key, priv_key) = generate_box_keypair();
        let derived = priv_key.public_key();
        assert_eq!(pub_key.as_bytes(), derived.as_bytes());
    }

    #[test]
    fn test_box_roundtrip() {
        let (alice_pub, alice_priv) = generate_box_keypair();
        let (bob_pub, bob_priv) = generate_box_keypair();

        let message = b"Hello, Yggdrasil!";
        let nonce = 42u64;

        // Alice encrypts to Bob
        let ciphertext = box_seal(message, nonce, &bob_pub, &alice_priv).unwrap();

        // Bob decrypts from Alice
        let plaintext = box_open(&ciphertext, nonce, &alice_pub, &bob_priv).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_shared_secret_encryption() {
        let (alice_pub, alice_priv) = generate_box_keypair();
        let (bob_pub, bob_priv) = generate_box_keypair();

        // Both sides compute the same shared secret
        let alice_shared = BoxShared::new(&bob_pub, &alice_priv);
        let bob_shared = BoxShared::new(&alice_pub, &bob_priv);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

        let message = b"Secret message";
        let nonce = 123u64;

        // Encrypt with Alice's shared secret
        let ciphertext = box_seal_with_shared(message, nonce, &alice_shared);

        // Decrypt with Bob's shared secret
        let plaintext = box_open_with_shared(&ciphertext, nonce, &bob_shared).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (alice_pub, alice_priv) = generate_box_keypair();
        let (bob_pub, bob_priv) = generate_box_keypair();
        let (_, eve_priv) = generate_box_keypair();

        let message = b"Secret message";
        let nonce = 1u64;

        // Alice encrypts to Bob
        let ciphertext = box_seal(message, nonce, &bob_pub, &alice_priv).unwrap();

        // Eve tries to decrypt with wrong key
        let result = box_open(&ciphertext, nonce, &alice_pub, &eve_priv);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_matters() {
        let (pub_key, priv_key) = generate_box_keypair();

        let message = b"Test message";

        // Encrypt with nonce 1
        let ciphertext = box_seal(message, 1, &pub_key, &priv_key).unwrap();

        // Try to decrypt with wrong nonce
        let result = box_open(&ciphertext, 2, &pub_key, &priv_key);
        assert!(result.is_err());
    }

    // === NaCl Box Compatibility Tests ===
    // These tests lock in the correct HSalsa20 behavior we've verified against Go
    
    /// Test that HSalsa20 produces the correct output for known inputs
    #[test]
    fn test_hsalsa20_known_vector() {
        let pub_key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let priv_key = hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        
        let their_pub = BoxPub::from_bytes(&pub_key).unwrap();
        let my_priv = BoxPriv::from_bytes(&priv_key).unwrap();
        
        let shared = BoxShared::new(&their_pub, &my_priv);
        
        // Expected shared secret (verified against golang.org/x/crypto/nacl/box)
        let expected = hex::decode("901205f8d288b240566c4a476b84283f21583db4ad30f802dfeb69f0da1061b8").unwrap();
        
        assert_eq!(
            shared.as_bytes(),
            expected.as_slice(),
            "HSalsa20 shared secret mismatch! BoxShared::new is broken."
        );
    }
    
    /// Test with real keys from white-box test
    #[test]
    fn test_whitebox_shared_secret() {
        let eph_pub = hex::decode("029b51683e11d112ff3f790b52fe7389658d185472417f66e4ee1f953b3bed5d").unwrap();
        let recv_priv = hex::decode("3ede643e1eaa8142a37e04da09cfd27e6a470d7b887f1b3df6b498d5de3e8952").unwrap();
        
        let their_pub = BoxPub::from_bytes(&eph_pub).unwrap();
        let my_priv = BoxPriv::from_bytes(&recv_priv).unwrap();
        
        let shared = BoxShared::new(&their_pub, &my_priv);
        
        // Expected shared secret (computed by yggdrasil-go)
        let expected = hex::decode("d3b139d8b5ccb73c2ac961dad181077a245d2b847779061cd7c774707ed32ab5").unwrap();
        
        assert_eq!(
            shared.as_bytes(),
            expected.as_slice(),
            "White-box shared secret mismatch! yggdrasil-go compatibility broken."
        );
    }
    
    /// Test full encryption/decryption cycle matches Go
    #[test]
    fn test_box_encryption_cycle() {
        let pub_key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let priv_key = hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        
        let their_pub = BoxPub::from_bytes(&pub_key).unwrap();
        let my_priv = BoxPriv::from_bytes(&priv_key).unwrap();
        
        let message = b"Hello, Yggdrasil!";
        let nonce = 0u64;
        
        // Use precomputed shared secret (our verified path)
        let shared = BoxShared::new(&their_pub, &my_priv);
        let encrypted = box_seal_with_shared(message, nonce, &shared);
        
        // Expected ciphertext (verified against Go)
        let expected_ct = hex::decode("bb5421d159a824d7d02d38a6986a7e97c6cbb8bbd9c83ec7e7fa1c24b6dd75a83c").unwrap();
        
        assert_eq!(
            encrypted,
            expected_ct,
            "Encrypted output doesn't match Go! Encryption broken."
        );
        
        // Verify decryption works
        let decrypted = box_open_with_shared(&encrypted, nonce, &shared).unwrap();
        assert_eq!(decrypted, message);
    }
    
    /// Regression test: Ensure we're using HSalsa20 with correct round count (10 rounds)
    #[test]
    fn test_hsalsa20_rounds_regression() {
        use x25519_dalek::{StaticSecret, PublicKey as X25519Public};
        use salsa20::hsalsa;
        use generic_array::GenericArray;
        
        let pub_bytes = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let priv_bytes = hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        
        let mut pub_key = [0u8; 32];
        let mut priv_key = [0u8; 32];
        pub_key.copy_from_slice(&pub_bytes);
        priv_key.copy_from_slice(&priv_bytes);
        
        let secret = StaticSecret::from(priv_key);
        let public = X25519Public::from(pub_key);
        let dh_result = secret.diffie_hellman(&public);
        
        // Apply HSalsa20 with CORRECT round count (U10 = 10 rounds)
        const ZERO: [u8; 16] = [0u8; 16];
        let key = GenericArray::from_slice(dh_result.as_bytes());
        let input = GenericArray::from_slice(&ZERO);
        let shared_correct = hsalsa::<typenum::consts::U10>(key, input);
        
        // This is what U20 (WRONG) would produce
        let shared_wrong = hsalsa::<typenum::consts::U20>(key, input);
        
        let expected_correct = hex::decode("901205f8d288b240566c4a476b84283f21583db4ad30f802dfeb69f0da1061b8").unwrap();
        let wrong_output = hex::decode("166723c086efd5c431699ab764ce44a6ac5d28ade5c0bdd5240987c0414c5eaf").unwrap();
        
        assert_eq!(
            shared_correct.as_slice(),
            expected_correct.as_slice(),
            "U10 (correct) must produce the right shared secret"
        );
        
        assert_eq!(
            shared_wrong.as_slice(),
            wrong_output.as_slice(),
            "U20 (wrong) produces different output - this documents the bug we fixed"
        );
        
        assert_ne!(
            shared_correct.as_slice(),
            shared_wrong.as_slice(),
            "U10 and U20 must produce different results"
        );
    }
}
