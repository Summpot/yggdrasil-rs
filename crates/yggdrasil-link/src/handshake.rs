//! Handshake protocol implementation.
//!
//! This module implements the version metadata exchange protocol
//! that occurs when two Yggdrasil nodes connect. The handshake
//! exchanges public keys and version information.
//!
//! Wire format (matching yggdrasil-go):
//! - 4 bytes: "meta" preamble
//! - 2 bytes: payload length (big-endian)
//! - payload: TLV-encoded fields
//! - 64 bytes: Ed25519 signature over BLAKE2b hash of public key with password

use std::io;

use blake2::digest::consts::U64;
use blake2::{Blake2b, Digest};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;
use yggdrasil_types::{PrivateKey, PublicKey, Signature};

/// Protocol version major - must match for peer compatibility.
pub const PROTOCOL_VERSION_MAJOR: u16 = 0;

/// Protocol version minor.
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

/// Ed25519 public key size.
const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size.
const SIGNATURE_SIZE: usize = 64;

/// TLV field types (matching yggdrasil-go).
const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

/// Handshake errors.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid preamble, remote side is not Yggdrasil")]
    InvalidPreamble,
    #[error("invalid handshake length, possible version mismatch")]
    InvalidLength,
    #[error("invalid password supplied, check your config")]
    InvalidPassword,
    #[error("password does not match remote side")]
    IncorrectPassword,
    #[error("hash failure")]
    HashFailure,
    #[error("connection to self")]
    ConnectionToSelf,
    #[error(
        "version mismatch: local {local_major}.{local_minor}, remote {remote_major}.{remote_minor}"
    )]
    VersionMismatch {
        local_major: u16,
        local_minor: u16,
        remote_major: u16,
        remote_minor: u16,
    },
    #[error("public key not in allowed list")]
    PublicKeyNotAllowed,
    #[error("invalid public key")]
    InvalidPublicKey,
}

/// Version metadata exchanged during handshake.
#[derive(Debug, Clone)]
pub struct VersionMetadata {
    /// Protocol major version.
    pub major_version: u16,
    /// Protocol minor version.
    pub minor_version: u16,
    /// Node's public key.
    pub public_key: PublicKey,
    /// Connection priority.
    pub priority: u8,
}

impl Default for VersionMetadata {
    fn default() -> Self {
        Self {
            major_version: PROTOCOL_VERSION_MAJOR,
            minor_version: PROTOCOL_VERSION_MINOR,
            public_key: PublicKey::default(),
            priority: 0,
        }
    }
}

impl VersionMetadata {
    /// Create base metadata with current protocol version.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create metadata with the given public key.
    pub fn with_key(public_key: PublicKey, priority: u8) -> Self {
        Self {
            major_version: PROTOCOL_VERSION_MAJOR,
            minor_version: PROTOCOL_VERSION_MINOR,
            public_key,
            priority,
        }
    }

    /// Encode the metadata into wire format.
    ///
    /// Format:
    /// - 4 bytes: "meta"
    /// - 2 bytes: payload length (big-endian)
    /// - TLV fields
    /// - 64 bytes: Ed25519 signature
    pub fn encode(
        &self,
        private_key: &PrivateKey,
        password: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        trace!(
            major = self.major_version,
            minor = self.minor_version,
            priority = self.priority,
            public_key = %hex::encode(self.public_key.as_bytes()),
            password_len = password.len(),
            "Encoding handshake metadata"
        );

        let mut buf = Vec::with_capacity(128);

        // Preamble
        buf.extend_from_slice(b"meta");

        // Placeholder for length
        buf.extend_from_slice(&[0u8; 2]);

        // Major version
        buf.extend_from_slice(&META_VERSION_MAJOR.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes()); // length
        buf.extend_from_slice(&self.major_version.to_be_bytes());

        // Minor version
        buf.extend_from_slice(&META_VERSION_MINOR.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes()); // length
        buf.extend_from_slice(&self.minor_version.to_be_bytes());

        // Public key
        buf.extend_from_slice(&META_PUBLIC_KEY.to_be_bytes());
        buf.extend_from_slice(&(PUBLIC_KEY_SIZE as u16).to_be_bytes());
        buf.extend_from_slice(self.public_key.as_bytes());

        // Priority
        buf.extend_from_slice(&META_PRIORITY.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // length
        buf.push(self.priority);

        // Compute BLAKE2b-512 hash with password key
        let hash = self.compute_hash(password)?;

        // Sign the hash
        let signature = private_key.sign(&hash);
        buf.extend_from_slice(signature.as_bytes());

        // Fill in the length (everything after the 6-byte header)
        let payload_len = (buf.len() - 6) as u16;
        buf[4..6].copy_from_slice(&payload_len.to_be_bytes());

        trace!(
            len = buf.len(),
            payload_len = payload_len,
            data_hex = %hex::encode(&buf),
            "Encoded handshake packet"
        );

        Ok(buf)
    }

    /// Decode metadata from a stream.
    pub async fn decode<R: AsyncRead + Unpin>(
        reader: &mut R,
        password: &[u8],
    ) -> Result<Self, HandshakeError> {
        trace!(
            password_len = password.len(),
            "Waiting to decode handshake metadata"
        );

        // Read header (4 bytes preamble + 2 bytes length)
        let mut header = [0u8; 6];
        reader.read_exact(&mut header).await?;

        trace!(
            header_hex = %hex::encode(&header),
            "Received handshake header"
        );

        // Check preamble
        if &header[0..4] != b"meta" {
            trace!(preamble = %String::from_utf8_lossy(&header[0..4]), "Invalid preamble");
            return Err(HandshakeError::InvalidPreamble);
        }

        // Get payload length
        let payload_len = u16::from_be_bytes([header[4], header[5]]) as usize;
        if payload_len < SIGNATURE_SIZE {
            return Err(HandshakeError::InvalidLength);
        }

        // Read payload
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;

        trace!(
            payload_len = payload_len,
            payload_hex = %hex::encode(&payload),
            "Received handshake payload"
        );

        // Extract signature (last 64 bytes)
        let sig_bytes: [u8; SIGNATURE_SIZE] =
            payload[payload_len - SIGNATURE_SIZE..].try_into().unwrap();
        let signature = Signature::from(sig_bytes);

        // Parse TLV fields from remaining payload
        let mut metadata = VersionMetadata::new();
        let tlv_data = &payload[..payload_len - SIGNATURE_SIZE];

        let mut offset = 0;
        while offset + 4 <= tlv_data.len() {
            let op = u16::from_be_bytes([tlv_data[offset], tlv_data[offset + 1]]);
            let op_len = u16::from_be_bytes([tlv_data[offset + 2], tlv_data[offset + 3]]) as usize;
            offset += 4;

            if offset + op_len > tlv_data.len() {
                break;
            }

            let value = &tlv_data[offset..offset + op_len];
            offset += op_len;

            match op {
                META_VERSION_MAJOR if value.len() >= 2 => {
                    metadata.major_version = u16::from_be_bytes([value[0], value[1]]);
                }
                META_VERSION_MINOR if value.len() >= 2 => {
                    metadata.minor_version = u16::from_be_bytes([value[0], value[1]]);
                }
                META_PUBLIC_KEY if value.len() >= PUBLIC_KEY_SIZE => {
                    let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
                    key_bytes.copy_from_slice(&value[..PUBLIC_KEY_SIZE]);
                    metadata.public_key = PublicKey::from(key_bytes);
                }
                META_PRIORITY if !value.is_empty() => {
                    metadata.priority = value[0];
                }
                _ => {
                    // Unknown field, skip
                }
            }
        }

        // Verify signature
        let hash = metadata.compute_hash(password)?;
        if !metadata.public_key.verify(&hash, &signature) {
            trace!(
                public_key = %hex::encode(metadata.public_key.as_bytes()),
                hash_hex = %hex::encode(&hash),
                "Signature verification failed - incorrect password or corrupted data"
            );
            return Err(HandshakeError::IncorrectPassword);
        }

        trace!(
            major = metadata.major_version,
            minor = metadata.minor_version,
            priority = metadata.priority,
            public_key = %hex::encode(metadata.public_key.as_bytes()),
            "Decoded handshake metadata successfully"
        );

        Ok(metadata)
    }

    /// Compute BLAKE2b-512 hash of public key with password as key.
    fn compute_hash(&self, password: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        // BLAKE2b-512 with password as key
        let mut hasher = Blake2b::<U64>::new_with_prefix(password);
        hasher.update(self.public_key.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    /// Check if this metadata is compatible with local version.
    pub fn check(&self) -> bool {
        self.major_version == PROTOCOL_VERSION_MAJOR
            && self.minor_version == PROTOCOL_VERSION_MINOR
            && self.public_key.as_bytes().len() == PUBLIC_KEY_SIZE
    }
}

/// Perform a handshake over a connection.
///
/// This sends our metadata and receives the remote's metadata.
pub async fn perform_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    our_private_key: &PrivateKey,
    priority: u8,
    password: &[u8],
) -> Result<VersionMetadata, HandshakeError> {
    let our_public_key = our_private_key.public_key();

    trace!(
        our_public_key = %hex::encode(our_public_key.as_bytes()),
        priority = priority,
        password_len = password.len(),
        "Starting handshake"
    );

    // Create our metadata
    let our_metadata = VersionMetadata::with_key(our_public_key.clone(), priority);

    // Encode and send our metadata
    let our_bytes = our_metadata.encode(our_private_key, password)?;
    trace!(len = our_bytes.len(), "Sending handshake data");
    stream.write_all(&our_bytes).await?;
    stream.flush().await?;
    trace!("Handshake data sent, waiting for remote metadata");

    // Receive and decode remote metadata
    let remote_metadata = VersionMetadata::decode(stream, password).await?;
    trace!(
        remote_public_key = %hex::encode(remote_metadata.public_key.as_bytes()),
        "Received remote metadata"
    );

    // Check version compatibility
    if !remote_metadata.check() {
        return Err(HandshakeError::VersionMismatch {
            local_major: PROTOCOL_VERSION_MAJOR,
            local_minor: PROTOCOL_VERSION_MINOR,
            remote_major: remote_metadata.major_version,
            remote_minor: remote_metadata.minor_version,
        });
    }

    // Check if connecting to self
    if remote_metadata.public_key == our_public_key {
        return Err(HandshakeError::ConnectionToSelf);
    }

    Ok(remote_metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_handshake_roundtrip() {
        let key_a = PrivateKey::generate();
        let key_b = PrivateKey::generate();
        let password = b"test_password";

        // Clone public keys before moving private keys into async blocks
        let pub_a = key_a.public_key();
        let pub_b = key_b.public_key();

        let (mut stream_a, mut stream_b) = duplex(1024);

        // Spawn both sides of the handshake
        let handle_a =
            tokio::spawn(
                async move { perform_handshake(&mut stream_a, &key_a, 0, password).await },
            );

        let handle_b =
            tokio::spawn(
                async move { perform_handshake(&mut stream_b, &key_b, 1, password).await },
            );

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);

        let meta_a = result_a.unwrap().unwrap();
        let meta_b = result_b.unwrap().unwrap();

        // A should have received B's key
        assert_eq!(meta_a.public_key, pub_b);
        // B should have received A's key
        assert_eq!(meta_b.public_key, pub_a);
    }

    #[tokio::test]
    async fn test_handshake_password_mismatch() {
        let key_a = PrivateKey::generate();
        let key_b = PrivateKey::generate();

        let (mut stream_a, mut stream_b) = duplex(1024);

        // A uses one password
        let handle_a = tokio::spawn(async move {
            perform_handshake(&mut stream_a, &key_a, 0, b"password_a").await
        });

        // B uses different password
        let handle_b = tokio::spawn(async move {
            perform_handshake(&mut stream_b, &key_b, 0, b"password_b").await
        });

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);

        // At least one should fail with incorrect password
        assert!(result_a.unwrap().is_err() || result_b.unwrap().is_err());
    }
}
