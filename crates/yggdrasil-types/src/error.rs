//! Error types for the Yggdrasil network.

use thiserror::Error;

/// Errors that can occur during wire protocol operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Failed to decode a message
    #[error("failed to decode message")]
    Decode,

    /// Failed to encode a message
    #[error("failed to encode message")]
    Encode,

    /// Message was empty when data was expected
    #[error("empty message")]
    EmptyMessage,

    /// Message was larger than allowed
    #[error("oversized message")]
    OversizedMessage,

    /// Received an unrecognized message type
    #[error("unrecognized message type")]
    UnrecognizedMessage,

    /// Message failed validation
    #[error("bad message")]
    BadMessage,

    /// Buffer too small for operation
    #[error("buffer too small")]
    BufferTooSmall,

    /// Invalid data in message
    #[error("invalid data")]
    InvalidData,
}

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid key length
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Failed to decrypt message
    #[error("decryption failed")]
    DecryptionFailed,

    /// Invalid public key
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid private key
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Key conversion failed
    #[error("key conversion failed")]
    KeyConversionFailed,
}

/// Errors related to network connections.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// Connection is closed
    #[error("connection closed")]
    Closed,

    /// Operation timed out
    #[error("operation timed out")]
    Timeout,

    /// Invalid network address
    #[error("invalid address")]
    BadAddress,

    /// Invalid key for connection
    #[error("invalid key")]
    BadKey,

    /// Peer not found
    #[error("peer not found")]
    PeerNotFound,

    /// Message too large
    #[error("message too large")]
    OversizedMessage,

    /// Connection refused
    #[error("connection refused")]
    ConnectionRefused,

    /// Already connected
    #[error("already connected")]
    AlreadyConnected,

    /// Node tried to connect to itself
    #[error("cannot connect to self")]
    ConnectToSelf,
}

/// Errors that can occur during session operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Session not found
    #[error("session not found")]
    NotFound,

    /// Session expired
    #[error("session expired")]
    Expired,

    /// Invalid session state
    #[error("invalid session state")]
    InvalidState,

    /// Nonce reuse detected
    #[error("nonce reuse detected")]
    NonceReuse,

    /// Key rotation required
    #[error("key rotation required")]
    KeyRotationRequired,
}

/// A unified error type for all Yggdrasil operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Wire(#[from] WireError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Network(#[from] NetworkError),

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

/// A specialized Result type for Yggdrasil operations.
pub type Result<T> = std::result::Result<T, Error>;
