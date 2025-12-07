//! Session initialization and acknowledgment messages.

use yggdrasil_crypto::{
    box_crypto::{self, BoxPriv, BoxPub},
    conversion::ed_to_curve25519_public,
};
use yggdrasil_types::{PublicKey, SecretKey, WireError};

use crate::{SESSION_ACK_SIZE, SESSION_INIT_SIZE};

/// Session initialization message.
#[derive(Debug, Clone)]
pub struct SessionInit {
    /// Current box public key.
    pub current: BoxPub,
    /// Next box public key (for ratcheting).
    pub next: BoxPub,
    /// Key sequence number.
    pub key_seq: u64,
    /// Sequence number (timestamp).
    pub seq: u64,
}

impl SessionInit {
    /// Create a new session init message.
    pub fn new(current: &BoxPub, next: &BoxPub, key_seq: u64) -> Self {
        Self {
            current: *current,
            next: *next,
            key_seq,
            seq: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Encrypt the session init message.
    pub fn encrypt(&self, from: &SecretKey, to: &PublicKey) -> Result<Vec<u8>, WireError> {
        tracing::debug!(
            to = %hex::encode(&to.as_bytes()[..8]),
            key_seq = self.key_seq,
            seq = self.seq,
            "Session Init: Encrypting Init message"
        );

        // Generate ephemeral box keys
        let (from_pub, from_priv) = box_crypto::generate_keypair();

        // Convert destination ed25519 key to curve25519
        let to_box = ed_to_curve25519_public(to).ok_or(WireError::InvalidData)?;

        // Build signature bytes
        let mut sig_bytes = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        sig_bytes.extend_from_slice(from_pub.as_bytes());
        sig_bytes.extend_from_slice(self.current.as_bytes());
        sig_bytes.extend_from_slice(self.next.as_bytes());
        sig_bytes.extend_from_slice(&self.key_seq.to_be_bytes());
        sig_bytes.extend_from_slice(&self.seq.to_be_bytes());

        // Sign using the seed (first 32 bytes of the 64-byte private key)
        let seed: [u8; 32] = from.as_bytes()[..32]
            .try_into()
            .map_err(|_| WireError::InvalidData)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&sig_bytes);

        // Build payload (signature + rest of sig_bytes excluding from_pub)
        let mut payload = Vec::with_capacity(64 + 32 + 32 + 8 + 8);
        payload.extend_from_slice(&sig.to_bytes());
        payload.extend_from_slice(&sig_bytes[32..]); // Skip from_pub

        // Encrypt with precomputed shared secret
        let shared = box_crypto::precompute(&to_box, &from_priv);
        let encrypted = box_crypto::seal_after_precomputation(&payload, 0, &shared);

        // Assemble final message
        let mut data = Vec::with_capacity(SESSION_INIT_SIZE);
        data.push(1); // sessionTypeInit
        data.extend_from_slice(from_pub.as_bytes());
        data.extend_from_slice(&encrypted);

        tracing::debug!(
            to = %hex::encode(&to.as_bytes()[..8]),
            data_len = data.len(),
            "Session Init: Init message encrypted successfully"
        );

        Ok(data)
    }

    /// Decrypt a session init message.
    pub fn decrypt(priv_key: &BoxPriv, from: &PublicKey, data: &[u8]) -> Option<Self> {
        tracing::debug!(
            from = %hex::encode(&from.as_bytes()[..8]),
            data_len = data.len(),
            expected_len = SESSION_INIT_SIZE,
            "Session Init: Attempting to decrypt Init message"
        );

        if data.len() != SESSION_INIT_SIZE {
            tracing::warn!(
                from = %hex::encode(&from.as_bytes()[..8]),
                data_len = data.len(),
                expected = SESSION_INIT_SIZE,
                "Session Init: Invalid Init message length"
            );
            return None;
        }

        // Parse ephemeral box public key
        let from_box = BoxPub::from_slice(&data[1..33])?;
        let encrypted = &data[33..];

        // Decrypt
        let shared = box_crypto::precompute(&from_box, priv_key);
        let payload = box_crypto::open_after_precomputation(encrypted, 0, &shared)?;

        if payload.len() < 64 + 32 + 32 + 8 + 8 {
            return None;
        }

        // Parse signature
        let sig_bytes: [u8; 64] = payload[0..64].try_into().ok()?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // Parse init fields
        let current = BoxPub::from_slice(&payload[64..96])?;
        let next = BoxPub::from_slice(&payload[96..128])?;
        let key_seq = u64::from_be_bytes(payload[128..136].try_into().ok()?);
        let seq = u64::from_be_bytes(payload[136..144].try_into().ok()?);

        // Verify signature
        let mut sig_bytes_full = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        sig_bytes_full.extend_from_slice(from_box.as_bytes());
        sig_bytes_full.extend_from_slice(&payload[64..]); // rest of payload

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(from.as_bytes()).ok()?;
        use ed25519_dalek::Verifier;
        verifying_key.verify(&sig_bytes_full, &sig).ok()?;

        tracing::info!(
            from = %hex::encode(&from.as_bytes()[..8]),
            current = %hex::encode(current.as_bytes()),
            next = %hex::encode(next.as_bytes()),
            key_seq = key_seq,
            seq = seq,
            "Session Init: Init message decrypted and verified successfully"
        );

        Some(Self {
            current,
            next,
            key_seq,
            seq,
        })
    }
}

/// Session acknowledgment message.
#[derive(Debug, Clone)]
pub struct SessionAck {
    /// The inner session init.
    pub inner: SessionInit,
}

impl SessionAck {
    /// Create a new session ack.
    pub fn new(init: SessionInit) -> Self {
        Self { inner: init }
    }

    /// Encrypt the session ack message.
    pub fn encrypt(&self, from: &SecretKey, to: &PublicKey) -> Result<Vec<u8>, WireError> {
        tracing::debug!(
            to = %hex::encode(&to.as_bytes()[..8]),
            "Session Ack: Encrypting Ack message"
        );
        let mut data = self.inner.encrypt(from, to)?;
        data[0] = 2; // sessionTypeAck
        tracing::debug!(
            to = %hex::encode(&to.as_bytes()[..8]),
            data_len = data.len(),
            "Session Ack: Ack message encrypted successfully"
        );
        Ok(data)
    }

    /// Decrypt a session ack message.
    pub fn decrypt(priv_key: &BoxPriv, from: &PublicKey, data: &[u8]) -> Option<Self> {
        tracing::debug!(
            from = %hex::encode(&from.as_bytes()[..8]),
            data_len = data.len(),
            packet_type = if data.len() > 0 { data[0] } else { 255 },
            "Session Ack: Attempting to decrypt Ack message"
        );

        if data.len() != SESSION_ACK_SIZE || data[0] != 2 {
            tracing::warn!(
                from = %hex::encode(&from.as_bytes()[..8]),
                data_len = data.len(),
                packet_type = if data.len() > 0 { data[0] } else { 255 },
                expected_len = SESSION_ACK_SIZE,
                expected_type = 2,
                "Session Ack: Invalid Ack message"
            );
            return None;
        }

        // Create a copy with init type for decryption
        let mut init_data = data.to_vec();
        init_data[0] = 1;

        SessionInit::decrypt(priv_key, from, &init_data).map(|init| Self { inner: init })
    }
}
