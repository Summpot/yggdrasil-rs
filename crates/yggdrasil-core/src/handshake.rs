use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

const PROTOCOL_VERSION_MAJOR: u16 = 0;
const PROTOCOL_VERSION_MINOR: u16 = 5;

const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

/// Handshake metadata
#[derive(Debug, Clone)]
pub struct HandshakeMetadata {
    pub major_ver: u16,
    pub minor_ver: u16,
    pub public_key: VerifyingKey,
    pub priority: u8,
}

impl HandshakeMetadata {
    /// Create new handshake metadata
    pub fn new(public_key: VerifyingKey, priority: u8) -> Self {
        Self {
            major_ver: PROTOCOL_VERSION_MAJOR,
            minor_ver: PROTOCOL_VERSION_MINOR,
            public_key,
            priority,
        }
    }
    
    /// Encode metadata to wire format
    pub fn encode(&self, signing_key: &SigningKey, password: &[u8]) -> Result<Vec<u8>> {
        let mut bs = Vec::with_capacity(128);
        
        // Preamble: "meta"
        bs.extend_from_slice(b"meta");
        
        // Length placeholder (2 bytes)
        bs.extend_from_slice(&[0, 0]);
        
        // Version major
        bs.extend_from_slice(&META_VERSION_MAJOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes()); // field length
        bs.extend_from_slice(&self.major_ver.to_be_bytes());
        
        // Version minor
        bs.extend_from_slice(&META_VERSION_MINOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes()); // field length
        bs.extend_from_slice(&self.minor_ver.to_be_bytes());
        
        // Public key
        bs.extend_from_slice(&META_PUBLIC_KEY.to_be_bytes());
        bs.extend_from_slice(&32u16.to_be_bytes()); // Ed25519 public key size
        bs.extend_from_slice(&self.public_key.to_bytes());
        
        // Priority
        bs.extend_from_slice(&META_PRIORITY.to_be_bytes());
        bs.extend_from_slice(&1u16.to_be_bytes()); // field length
        bs.push(self.priority);
        
        // Sign the public key with password as key
        let hash = blake2b_hash(&self.public_key.to_bytes(), password)?;
        let signature = signing_key.sign(&hash);
        bs.extend_from_slice(&signature.to_bytes());
        
        // Fill in the length field
        let msg_len = (bs.len() - 6) as u16;
        bs[4..6].copy_from_slice(&msg_len.to_be_bytes());
        
        Ok(bs)
    }
    
    /// Decode metadata from wire format
    pub async fn decode<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        password: &[u8],
    ) -> Result<Self> {
        // Read preamble and length
        let mut header = [0u8; 6];
        reader.read_exact(&mut header).await
            .context("Failed to read handshake header")?;
        
        if &header[0..4] != b"meta" {
            anyhow::bail!("Invalid handshake preamble");
        }
        
        let msg_len = u16::from_be_bytes([header[4], header[5]]) as usize;
        if msg_len < 64 {
            anyhow::bail!("Invalid handshake length");
        }
        
        // Read message body
        let mut body = vec![0u8; msg_len];
        reader.read_exact(&mut body).await
            .context("Failed to read handshake body")?;
        
        // Extract signature (last 64 bytes)
        if body.len() < 64 {
            anyhow::bail!("Handshake too short for signature");
        }
        let sig_bytes = &body[body.len() - 64..];
        let signature = Signature::from_bytes(sig_bytes.try_into().unwrap());
        let fields = &body[..body.len() - 64];
        
        // Parse fields
        let mut metadata = HandshakeMetadata {
            major_ver: 0,
            minor_ver: 0,
            public_key: VerifyingKey::from_bytes(&[0u8; 32])?,
            priority: 0,
        };
        
        let mut pos = 0;
        while pos + 4 <= fields.len() {
            let op = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
            let op_len = u16::from_be_bytes([fields[pos + 2], fields[pos + 3]]) as usize;
            pos += 4;
            
            if pos + op_len > fields.len() {
                break;
            }
            
            match op {
                META_VERSION_MAJOR => {
                    metadata.major_ver = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
                }
                META_VERSION_MINOR => {
                    metadata.minor_ver = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
                }
                META_PUBLIC_KEY => {
                    let key_bytes: [u8; 32] = fields[pos..pos + 32].try_into()
                        .context("Invalid public key length")?;
                    metadata.public_key = VerifyingKey::from_bytes(&key_bytes)?;
                }
                META_PRIORITY => {
                    metadata.priority = fields[pos];
                }
                _ => {} // Unknown field, skip
            }
            
            pos += op_len;
        }
        
        // Verify signature
        let hash = blake2b_hash(&metadata.public_key.to_bytes(), password)?;
        metadata.public_key.verify(&hash, &signature)
            .context("Invalid handshake signature")?;
        
        Ok(metadata)
    }
    
    /// Check if version is compatible
    pub fn is_compatible(&self) -> bool {
        self.major_ver == PROTOCOL_VERSION_MAJOR && self.minor_ver == PROTOCOL_VERSION_MINOR
    }
}

/// Perform handshake on a stream
pub async fn perform_handshake<S>(
    stream: &mut S,
    signing_key: &SigningKey,
    priority: u8,
    password: &[u8],
    timeout: Duration,
) -> Result<HandshakeMetadata>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    perform_handshake_with_validation(stream, signing_key, priority, password, timeout, None).await
}

/// Perform handshake with public key whitelist validation
pub async fn perform_handshake_with_validation<S>(
    stream: &mut S,
    signing_key: &SigningKey,
    priority: u8,
    password: &[u8],
    timeout: Duration,
    allowed_public_keys: Option<&[String]>,
) -> Result<HandshakeMetadata>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Send our metadata
    let our_meta = HandshakeMetadata::new(signing_key.verifying_key(), priority);
    let encoded = our_meta.encode(signing_key, password)?;
    
    // Set deadline for handshake
    let send_future = stream.write_all(&encoded);
    tokio::time::timeout(timeout, send_future).await
        .context("Handshake send timeout")??;
    
    stream.flush().await
        .context("Failed to flush handshake")?;
    
    // Receive peer metadata
    let recv_future = HandshakeMetadata::decode(stream, password);
    let peer_meta = tokio::time::timeout(timeout, recv_future).await
        .context("Handshake receive timeout")??;
    
    // Check compatibility
    if !peer_meta.is_compatible() {
        anyhow::bail!(
            "Incompatible protocol version: local {}.{}, remote {}.{}",
            PROTOCOL_VERSION_MAJOR,
            PROTOCOL_VERSION_MINOR,
            peer_meta.major_ver,
            peer_meta.minor_ver
        );
    }
    
    // Validate public key against whitelist if provided
    if let Some(allowed_keys) = allowed_public_keys {
        if !allowed_keys.is_empty() {
            let peer_key_hex = hex::encode(peer_meta.public_key.to_bytes());
            
            if !allowed_keys.iter().any(|k| k.to_lowercase() == peer_key_hex.to_lowercase()) {
                anyhow::bail!(
                    "Public key not in whitelist: {}",
                    peer_key_hex
                );
            }
        }
    }
    
    Ok(peer_meta)
}

/// Hash using BLAKE2b with password as key
fn blake2b_hash(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    use blake2::{Blake2b512, Digest};
    
    let mut hasher = Blake2b512::new();
    
    // If password is provided, mix it in
    if !password.is_empty() {
        hasher.update(password);
    }
    
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;
    
    #[test]
    fn test_metadata_encoding() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let meta = HandshakeMetadata::new(signing_key.verifying_key(), 8);
        let password = b"test_password";
        
        let encoded = meta.encode(&signing_key, password).unwrap();
        
        // Check preamble
        assert_eq!(&encoded[0..4], b"meta");
        
        // Check minimum length
        assert!(encoded.len() > 64);
    }
    
    #[tokio::test]
    async fn test_metadata_round_trip() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let meta = HandshakeMetadata::new(signing_key.verifying_key(), 8);
        let password = b"test_password";
        
        let encoded = meta.encode(&signing_key, password).unwrap();
        let mut reader = BufReader::new(&encoded[..]);
        
        let decoded = HandshakeMetadata::decode(&mut reader, password).await.unwrap();
        
        assert_eq!(decoded.major_ver, meta.major_ver);
        assert_eq!(decoded.minor_ver, meta.minor_ver);
        assert_eq!(decoded.public_key.to_bytes(), meta.public_key.to_bytes());
        assert_eq!(decoded.priority, meta.priority);
    }
    
    #[tokio::test]
    async fn test_handshake_with_wrong_password() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let meta = HandshakeMetadata::new(signing_key.verifying_key(), 8);
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        
        let encoded = meta.encode(&signing_key, password).unwrap();
        let mut reader = BufReader::new(&encoded[..]);
        
        let result = HandshakeMetadata::decode(&mut reader, wrong_password).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_version_compatibility() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let meta = HandshakeMetadata::new(signing_key.verifying_key(), 8);
        
        assert!(meta.is_compatible());
        
        let mut incompatible_meta = meta.clone();
        incompatible_meta.major_ver = 99;
        assert!(!incompatible_meta.is_compatible());
    }
    
    #[tokio::test]
    async fn test_full_handshake() {
        use tokio::io::duplex;
        
        let signing_key1 = SigningKey::from_bytes(&[1u8; 32]);
        let signing_key2 = SigningKey::from_bytes(&[2u8; 32]);
        let password = b"shared_password";
        
        let (mut client, mut server) = duplex(1024);
        
        // Spawn server handshake
        let server_key = signing_key2.clone();
        let server_handle = tokio::spawn(async move {
            perform_handshake(&mut server, &server_key, 5, password, Duration::from_secs(5)).await
        });
        
        // Perform client handshake
        let client_meta = perform_handshake(
            &mut client,
            &signing_key1,
            10,
            password,
            Duration::from_secs(5),
        ).await.unwrap();
        
        // Wait for server
        let server_meta = server_handle.await.unwrap().unwrap();
        
        // Verify we received each other's keys
        assert_eq!(client_meta.public_key.to_bytes(), signing_key2.verifying_key().to_bytes());
        assert_eq!(server_meta.public_key.to_bytes(), signing_key1.verifying_key().to_bytes());
        assert_eq!(client_meta.priority, 5);
        assert_eq!(server_meta.priority, 10);
    }
}
