use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Cryptography utility module
#[derive(Clone)]
pub struct Crypto {
    signing_key: SigningKey,
}

impl Crypto {
    /// Create Crypto instance from private key
    pub fn from_private_key(private_key: [u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(&private_key);
        Ok(Crypto { signing_key })
    }

    /// Get public key
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get signing key reference
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Verify signature
    pub fn verify(public_key: &VerifyingKey, data: &[u8], signature: &Signature) -> bool {
        public_key.verify(data, signature).is_ok()
    }
}

/// Key exchange
pub mod key_exchange {
    use anyhow::Result;
    use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
    use ring::rand::SystemRandom;

    /// Generate key exchange keypair
    pub fn generate_keypair() -> Result<(EphemeralPrivateKey, Vec<u8>)> {
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate private key"))?;

        let public_key = private_key
            .compute_public_key()
            .map_err(|_| anyhow::anyhow!("Failed to compute public key"))?;

        Ok((private_key, public_key.as_ref().to_vec()))
    }

    /// Perform key exchange
    pub fn exchange(private_key: EphemeralPrivateKey, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let peer_public_key = UnparsedPublicKey::new(&X25519, peer_public_key);

        agree_ephemeral(private_key, &peer_public_key, |key_material| {
            Ok(key_material.to_vec())
        })
        .map_err(|_| anyhow::anyhow!("Key exchange failed"))?
    }
}

/// Encryption and decryption
pub mod cipher {
    use anyhow::Result;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("Failed to create encryption key"))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::assume_unique_for_key(*nonce);
        let aad = Aad::from(aad);

        let mut in_out = plaintext.to_vec();
        less_safe_key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        Ok(in_out)
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("Failed to create decryption key"))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::assume_unique_for_key(*nonce);
        let aad = Aad::from(aad);

        let mut in_out = ciphertext.to_vec();
        less_safe_key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        // Remove authentication tag
        let tag_len = AES_256_GCM.tag_len();
        in_out.truncate(in_out.len() - tag_len);

        Ok(in_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        // Use from_bytes to create key instead of generate
        let secret = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let crypto = Crypto::from_private_key(signing_key.to_bytes()).unwrap();

        let data = b"test data";
        let signature = crypto.sign(data);

        assert!(Crypto::verify(&crypto.public_key(), data, &signature));
    }

    #[test]
    fn test_key_exchange() {
        let (private_key1, public_key1) = key_exchange::generate_keypair().unwrap();
        let (private_key2, public_key2) = key_exchange::generate_keypair().unwrap();

        let shared_secret1 = key_exchange::exchange(private_key1, &public_key2).unwrap();
        let shared_secret2 = key_exchange::exchange(private_key2, &public_key1).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, Yggdrasil!";
        let aad = b"additional data";

        let ciphertext = cipher::encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = cipher::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
