//! Session encryption layer for the Yggdrasil network.
//!
//! This crate implements encrypted sessions between nodes using a double-ratchet
//! inspired protocol with NaCl box encryption.

mod buffer;
mod info;
mod init;
mod manager;

pub use buffer::SessionBuffer;
pub use info::SessionInfo;
pub use init::{SessionAck, SessionInit};
pub use manager::{HandleResult, SessionManager, SessionStats, WriteResult};

use std::time::Duration;

/// Session timeout duration.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimum traffic overhead for session messages.
pub const SESSION_TRAFFIC_OVERHEAD_MIN: usize = 1 + 1 + 1 + 1 + 16 + 32; // header, seq, seq, nonce, box overhead, box pub

/// Maximum traffic overhead for session messages.
pub const SESSION_TRAFFIC_OVERHEAD: usize = SESSION_TRAFFIC_OVERHEAD_MIN + 9 + 9 + 9;

/// Size of session init messages.
pub const SESSION_INIT_SIZE: usize = 1 + 32 + 16 + 64 + 32 + 32 + 8 + 8;

/// Size of session ack messages.
pub const SESSION_ACK_SIZE: usize = SESSION_INIT_SIZE;

/// Session message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionType {
    /// Dummy message (ignored).
    Dummy = 0,
    /// Session initialization message.
    Init = 1,
    /// Session acknowledgment message.
    Ack = 2,
    /// Encrypted traffic.
    Traffic = 3,
}

impl SessionType {
    /// Parse a session type from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Dummy),
            1 => Some(Self::Init),
            2 => Some(Self::Ack),
            3 => Some(Self::Traffic),
            _ => None,
        }
    }
}
