//! Session buffer for pending session establishment.

use std::time::Instant;

use yggdrasil_crypto::box_crypto::{BoxPriv, BoxPub};

use crate::SessionInit;

/// Buffer for session data before the session is established.
#[derive(Debug)]
pub struct SessionBuffer {
    /// Buffered data to send once session is established.
    pub data: Option<Vec<u8>>,
    /// Session init to send.
    pub init: SessionInit,
    /// Private key for current box key.
    pub current_priv: BoxPriv,
    /// Private key for next box key.
    pub next_priv: BoxPriv,
    /// Time when this buffer was created.
    pub created_at: Instant,
}

impl SessionBuffer {
    /// Create a new session buffer.
    pub fn new(
        current_pub: BoxPub,
        current_priv: BoxPriv,
        next_pub: BoxPub,
        next_priv: BoxPriv,
    ) -> Self {
        Self {
            data: None,
            init: SessionInit::new(&current_pub, &next_pub, 0),
            current_priv,
            next_priv,
            created_at: Instant::now(),
        }
    }

    /// Check if this buffer has expired.
    pub fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.created_at.elapsed() > timeout
    }
}
