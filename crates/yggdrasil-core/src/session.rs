use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use log::{info, warn};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::address::Address;

/// Session timeout duration (5 minutes)
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Session nonce size for AES-GCM
const NONCE_SIZE: usize = 12;

/// Session state
#[derive(Debug, Clone)]
pub struct Session {
    /// Remote peer's Ed25519 public key (identity)
    pub peer_key: VerifyingKey,
    /// Remote peer's IPv6 address
    pub peer_addr: Ipv6Addr,
    /// Shared secret for encryption
    shared_secret: Vec<u8>,
    /// Last activity timestamp
    last_activity: Instant,
    /// Bytes sent in this session
    pub bytes_sent: u64,
    /// Bytes received in this session
    pub bytes_received: u64,
}

impl Session {
    /// Create new session with shared secret
    pub fn new(peer_key: VerifyingKey, shared_secret: Vec<u8>) -> Self {
        let peer_addr = Address::from_public_key(&peer_key).as_ipv6();

        Session {
            peer_key,
            peer_addr,
            shared_secret,
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Derive shared secret from peer keys
    /// This is a simplified version using SHA-256
    /// In production, proper ECDH key exchange should be used
    pub fn derive_shared_secret(
        our_private_key: &[u8; 32],
        their_public_key: &VerifyingKey,
    ) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};

        // Combine our private key and their public key
        let mut hasher = Sha256::new();
        hasher.update(b"yggdrasil-session-key");
        hasher.update(our_private_key);
        hasher.update(their_public_key.to_bytes());

        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

        // Create encryption key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.shared_secret)
            .map_err(|_| anyhow::anyhow!("Failed to create encryption key"))?;
        let key = LessSafeKey::new(unbound_key);

        // Prepare output buffer (nonce + ciphertext + tag)
        let mut in_out = plaintext.to_vec();

        // Encrypt in place
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        // Prepend nonce to ciphertext
        let mut output = Vec::with_capacity(NONCE_SIZE + in_out.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&in_out);

        Ok(output)
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            anyhow::bail!("Ciphertext too short");
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);

        // Create decryption key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.shared_secret)
            .map_err(|_| anyhow::anyhow!("Failed to create decryption key"))?;
        let key = LessSafeKey::new(unbound_key);

        // Decrypt in place
        let mut in_out = encrypted.to_vec();
        let mut nonce_arr = [0u8; NONCE_SIZE];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        Ok(plaintext.to_vec())
    }

    /// Update activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if session has timed out
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Update statistics
    pub fn update_stats(&mut self, bytes_sent: u64, bytes_received: u64) {
        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_received;
        self.update_activity();
    }
}

/// Session manager
#[derive(Clone)]
pub struct SessionManager {
    /// Active sessions (peer public key -> session)
    sessions: Arc<RwLock<HashMap<[u8; 32], Session>>>,
    /// Session timeout duration
    timeout: Duration,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(SESSION_TIMEOUT)
    }
}

impl SessionManager {
    /// Create new session manager
    pub fn new(timeout: Duration) -> Self {
        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timeout,
        }
    }

    /// Add or update session
    pub async fn add_session(&self, session: Session) -> Result<()> {
        let key_bytes = session.peer_key.to_bytes();
        let mut sessions = self.sessions.write().await;

        info!(
            "Adding session for peer {}",
            Address::from_public_key(&session.peer_key)
        );

        sessions.insert(key_bytes, session);
        Ok(())
    }

    /// Get session by peer key
    pub async fn get_session(&self, peer_key: &VerifyingKey) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(&peer_key.to_bytes()).cloned()
    }

    /// Get session by peer address
    pub async fn get_session_by_addr(&self, addr: &Ipv6Addr) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.values().find(|s| &s.peer_addr == addr).cloned()
    }

    /// Remove session
    pub async fn remove_session(&self, peer_key: &VerifyingKey) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        if sessions.remove(&peer_key.to_bytes()).is_some() {
            info!(
                "Removed session for peer {}",
                Address::from_public_key(peer_key)
            );
        }

        Ok(())
    }

    /// Update session activity
    pub async fn update_activity(&self, peer_key: &VerifyingKey) {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(&peer_key.to_bytes()) {
            session.update_activity();
        }
    }

    /// Update session statistics
    pub async fn update_stats(
        &self,
        peer_key: &VerifyingKey,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(&peer_key.to_bytes()) {
            session.update_stats(bytes_sent, bytes_received);
        }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> Vec<VerifyingKey> {
        let mut sessions = self.sessions.write().await;
        let mut expired = Vec::new();
        let mut to_remove = Vec::new();

        for (key_bytes, session) in sessions.iter() {
            if session.is_expired(self.timeout) {
                match VerifyingKey::from_bytes(key_bytes) {
                    Ok(peer_key) => {
                        warn!(
                            "Session expired for peer {}",
                            Address::from_public_key(&peer_key)
                        );
                        expired.push(peer_key);
                        to_remove.push(*key_bytes);
                    }
                    Err(_) => {
                        warn!("Failed to deserialize expired peer key");
                        to_remove.push(*key_bytes);
                    }
                }
            }
        }

        // Remove expired sessions
        for key in to_remove {
            sessions.remove(&key);
        }

        if !expired.is_empty() {
            info!("Cleaned up {} expired sessions", expired.len());
        }

        expired
    }

    /// Get all active sessions
    pub async fn get_all_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Get session count
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;

        let total = sessions.len();
        let total_bytes_sent = sessions.values().map(|s| s.bytes_sent).sum();
        let total_bytes_received = sessions.values().map(|s| s.bytes_received).sum();

        SessionStats {
            total,
            total_bytes_sent,
            total_bytes_received,
        }
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn generate_test_key() -> VerifyingKey {
        let signing_key = SigningKey::from_bytes(&rand::random());
        signing_key.verifying_key()
    }

    #[test]
    fn test_session_creation() {
        let peer_key = generate_test_key();
        let shared_secret = vec![0u8; 32];

        let session = Session::new(peer_key, shared_secret);
        assert_eq!(session.peer_key, peer_key);
        assert!(!session.is_expired(SESSION_TIMEOUT));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let peer_key = generate_test_key();

        // Use a proper 32-byte key for AES-256
        let shared_secret = vec![1u8; 32];
        let session = Session::new(peer_key, shared_secret);

        let plaintext = b"Hello, Yggdrasil!";
        let ciphertext = session.encrypt(plaintext).unwrap();

        assert_ne!(ciphertext.as_slice(), plaintext);
        assert!(ciphertext.len() > plaintext.len()); // Includes nonce and tag

        let decrypted = session.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_invalid_ciphertext() {
        let peer_key = generate_test_key();
        let shared_secret = vec![1u8; 32];
        let session = Session::new(peer_key, shared_secret);

        // Too short
        let result = session.decrypt(&[0u8; 5]);
        assert!(result.is_err());

        // Invalid data
        let invalid = vec![0u8; 50];
        let result = session.decrypt(&invalid);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_manager() {
        let manager = SessionManager::default();

        let peer_key = generate_test_key();
        let shared_secret = vec![1u8; 32];
        let session = Session::new(peer_key, shared_secret);

        // Add session
        manager.add_session(session.clone()).await.unwrap();
        assert_eq!(manager.session_count().await, 1);

        // Get session
        let retrieved = manager.get_session(&peer_key).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().peer_key, peer_key);

        // Remove session
        manager.remove_session(&peer_key).await.unwrap();
        assert_eq!(manager.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let timeout = Duration::from_millis(50);
        let manager = SessionManager::new(timeout);

        let peer_key = generate_test_key();
        let shared_secret = vec![1u8; 32];
        let session = Session::new(peer_key, shared_secret);

        manager.add_session(session).await.unwrap();
        let count = manager.session_count().await;
        assert_eq!(count, 1);

        // Wait for expiration (with extra buffer)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cleanup should remove expired session
        let expired = manager.cleanup_expired().await;
        assert_eq!(expired.len(), 1);
        assert_eq!(manager.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_stats() {
        let manager = SessionManager::default();

        let peer_key = generate_test_key();
        let shared_secret = vec![1u8; 32];
        let mut session = Session::new(peer_key, shared_secret);

        // Update stats
        session.update_stats(100, 200);
        manager.add_session(session).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total, 1);
        assert_eq!(stats.total_bytes_sent, 100);
        assert_eq!(stats.total_bytes_received, 200);
    }
}
