//! Multicast advertisement message.

use std::io;

use yggdrasil_types::PublicKey;

/// Protocol version major (must match for peer discovery).
pub const PROTOCOL_VERSION_MAJOR: u16 = 0;

/// Protocol version minor.
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

/// Multicast advertisement structure.
///
/// This is sent over UDP multicast to announce a node's presence on the network.
/// The format matches the Go implementation for wire compatibility.
#[derive(Debug, Clone)]
pub struct MulticastAdvertisement {
    /// Protocol major version.
    pub major_version: u16,
    /// Protocol minor version.
    pub minor_version: u16,
    /// The node's public key.
    pub public_key: [u8; 32],
    /// The TCP port the node is listening on.
    pub port: u16,
    /// BLAKE2b hash for password verification.
    pub hash: Vec<u8>,
}

impl MulticastAdvertisement {
    /// Create a new multicast advertisement.
    pub fn new(public_key: &PublicKey, port: u16, hash: Vec<u8>) -> Self {
        Self {
            major_version: PROTOCOL_VERSION_MAJOR,
            minor_version: PROTOCOL_VERSION_MINOR,
            public_key: *public_key.as_bytes(),
            port,
            hash,
        }
    }

    /// Serialize the advertisement to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Format: major(2) + minor(2) + pubkey(32) + port(2) + hash_len(2) + hash
        let mut buf = Vec::with_capacity(32 + 8 + self.hash.len());
        buf.extend_from_slice(&self.major_version.to_be_bytes());
        buf.extend_from_slice(&self.minor_version.to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(&(self.hash.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.hash);
        buf
    }

    /// Parse an advertisement from bytes.
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < 32 + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid multicast beacon",
            ));
        }

        let major_version = u16::from_be_bytes([data[0], data[1]]);
        let minor_version = u16::from_be_bytes([data[2], data[3]]);

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[4..36]);

        let port = u16::from_be_bytes([data[36], data[37]]);
        let hash_len = u16::from_be_bytes([data[38], data[39]]) as usize;

        if data.len() < 40 + hash_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid multicast beacon hash length",
            ));
        }

        let hash = data[40..40 + hash_len].to_vec();

        Ok(Self {
            major_version,
            minor_version,
            public_key,
            port,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertisement_roundtrip() {
        let public_key = [1u8; 32];
        let pk = PublicKey::from(public_key);
        let hash = vec![2u8; 64];

        let adv = MulticastAdvertisement::new(&pk, 12345, hash.clone());
        let bytes = adv.to_bytes();
        let parsed = MulticastAdvertisement::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.major_version, PROTOCOL_VERSION_MAJOR);
        assert_eq!(parsed.minor_version, PROTOCOL_VERSION_MINOR);
        assert_eq!(parsed.public_key, public_key);
        assert_eq!(parsed.port, 12345);
        assert_eq!(parsed.hash, hash);
    }
}
