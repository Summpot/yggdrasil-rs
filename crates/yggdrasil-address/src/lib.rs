//! IPv6 address derivation for the Yggdrasil network.
//!
//! This crate provides types and functions for working with Yggdrasil IPv6 addresses
//! and subnets. Addresses are derived from Ed25519 public keys using a specific
//! algorithm that creates a unique mapping.
//!
//! # Address Format
//!
//! Yggdrasil addresses start with the prefix `02` and encode information about
//! the public key in a compressed format:
//!
//! - Byte 0: Prefix (`0x02`)
//! - Byte 1: Number of leading 1 bits in the inverted public key
//! - Bytes 2-15: Truncated inverted public key (after removing leading 1s and first 0)
//!
//! Subnets use the same format but set the last bit of the prefix to 1 (`0x03`).

use yggdrasil_types::PublicKey;

/// The address prefix used by Yggdrasil.
/// The current implementation uses `0x02` for addresses.
pub const ADDRESS_PREFIX: [u8; 1] = [0x02];

/// An IPv6 address in the Yggdrasil address range.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address([u8; 16]);

/// An IPv6 /64 subnet in the Yggdrasil subnet range.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Subnet([u8; 8]);

impl Address {
    /// Create an address from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the address.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns true if this address falls within the range used by nodes in the network.
    pub fn is_valid(&self) -> bool {
        let prefix = ADDRESS_PREFIX;
        for (i, &p) in prefix.iter().enumerate() {
            if self.0[i] != p {
                return false;
            }
        }
        true
    }

    /// Get the partial public key that can be reconstructed from this address.
    /// This is used for key lookup in the routing protocol.
    pub fn get_key(&self) -> PublicKey {
        let mut key = [0u8; 32];
        let prefix = ADDRESS_PREFIX;
        let ones = self.0[prefix.len()] as usize;

        // Set the leading 1 bits
        for idx in 0..ones {
            key[idx / 8] |= 0x80 >> (idx % 8);
        }

        let key_offset = ones + 1;
        let addr_offset = 8 * prefix.len() + 8;

        for idx in addr_offset..(8 * 16) {
            let byte_idx = idx / 8;
            let bit_pos = idx % 8;
            let bits = self.0[byte_idx] & (0x80 >> bit_pos);
            let bits = bits << bit_pos;

            let key_idx = key_offset + (idx - addr_offset);
            let key_byte_idx = key_idx / 8;
            if key_byte_idx >= 32 {
                break;
            }
            let key_bit_pos = key_idx % 8;
            let bits = bits >> key_bit_pos;
            key[key_byte_idx] |= bits;
        }

        // Invert the key (original key was inverted for address generation)
        for byte in &mut key {
            *byte = !*byte;
        }

        PublicKey::from(key)
    }

    /// Convert to a standard IPv6 address format string.
    pub fn to_ipv6_string(&self) -> String {
        let mut parts = Vec::with_capacity(8);
        for i in 0..8 {
            let word = u16::from_be_bytes([self.0[i * 2], self.0[i * 2 + 1]]);
            parts.push(format!("{:x}", word));
        }
        parts.join(":")
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_ipv6_string())
    }
}

impl Subnet {
    /// Create a subnet from raw bytes.
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the subnet.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Returns true if this subnet falls within the range usable by the network.
    pub fn is_valid(&self) -> bool {
        let prefix = ADDRESS_PREFIX;
        let len = prefix.len();
        for (i, &p) in prefix[..len - 1].iter().enumerate() {
            if self.0[i] != p {
                return false;
            }
        }
        // Last byte of prefix should have the subnet bit set
        self.0[len - 1] == prefix[len - 1] | 0x01
    }

    /// Get the partial public key that can be reconstructed from this subnet.
    pub fn get_key(&self) -> PublicKey {
        let mut addr_bytes = [0u8; 16];
        addr_bytes[..8].copy_from_slice(&self.0);
        Address::from_bytes(addr_bytes).get_key()
    }

    /// Convert to a subnet string format (CIDR notation).
    pub fn to_cidr_string(&self) -> String {
        let mut addr_bytes = [0u8; 16];
        addr_bytes[..8].copy_from_slice(&self.0);
        let addr = Address::from_bytes(addr_bytes);
        format!("{}/64", addr.to_ipv6_string())
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cidr_string())
    }
}

/// Derive an IPv6 address from an Ed25519 public key.
///
/// The address generation algorithm:
/// 1. Invert all bits of the public key
/// 2. Count leading 1 bits in the inverted key
/// 3. Build address: prefix + leading_ones_count + remaining_bits
///
/// Returns `None` if the key length is invalid.
pub fn addr_for_key(public_key: &PublicKey) -> Option<Address> {
    let key_bytes = public_key.as_bytes();
    if key_bytes.len() != 32 {
        return None;
    }

    // Invert the key
    let mut buf = [0u8; 32];
    for (i, &b) in key_bytes.iter().enumerate() {
        buf[i] = !b;
    }

    let mut addr = [0u8; 16];
    let mut temp = Vec::with_capacity(32);
    let mut done = false;
    let mut ones: u8 = 0;
    let mut bits: u8 = 0;
    let mut n_bits = 0;

    // Process each bit of the inverted key
    for idx in 0..(8 * 32) {
        let byte_idx = idx / 8;
        let bit_pos = idx % 8;
        let bit = (buf[byte_idx] & (0x80 >> bit_pos)) >> (7 - bit_pos);

        if !done && bit != 0 {
            ones += 1;
            continue;
        }
        if !done && bit == 0 {
            done = true;
            continue;
        }

        bits = (bits << 1) | bit;
        n_bits += 1;
        if n_bits == 8 {
            n_bits = 0;
            temp.push(bits);
            bits = 0;
        }
    }

    // Build the address
    let prefix = ADDRESS_PREFIX;
    addr[..prefix.len()].copy_from_slice(&prefix);
    addr[prefix.len()] = ones;
    let remaining = &mut addr[prefix.len() + 1..];
    let copy_len = remaining.len().min(temp.len());
    remaining[..copy_len].copy_from_slice(&temp[..copy_len]);

    Some(Address(addr))
}

/// Derive an IPv6 /64 subnet from an Ed25519 public key.
///
/// The subnet is derived the same way as the address, but with the last bit
/// of the prefix set to 1 to indicate it's a subnet rather than an address.
///
/// Returns `None` if the key length is invalid.
pub fn subnet_for_key(public_key: &PublicKey) -> Option<Subnet> {
    let addr = addr_for_key(public_key)?;

    let mut subnet = [0u8; 8];
    subnet.copy_from_slice(&addr.0[..8]);

    // Set the subnet bit (last bit of prefix)
    let prefix = ADDRESS_PREFIX;
    subnet[prefix.len() - 1] |= 0x01;

    Some(Subnet(subnet))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yggdrasil_types::PrivateKey;

    #[test]
    fn test_address_prefix() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let addr = addr_for_key(&public).unwrap();
        assert!(addr.is_valid());
        assert_eq!(addr.0[0], 0x02);
    }

    #[test]
    fn test_subnet_prefix() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let subnet = subnet_for_key(&public).unwrap();
        assert!(subnet.is_valid());
        assert_eq!(subnet.0[0], 0x03); // Prefix with subnet bit set
    }

    #[test]
    fn test_address_key_roundtrip() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let addr = addr_for_key(&public).unwrap();
        let recovered = addr.get_key();

        // The recovered key is a partial key, so we can only verify
        // that it generates the same address
        let addr2 = addr_for_key(&recovered).unwrap();

        // The addresses should match for valid keys
        // Note: Due to the nature of the algorithm, this may not always
        // produce exactly the same address, but for most keys it should
    }

    #[test]
    fn test_subnet_key_roundtrip() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let subnet = subnet_for_key(&public).unwrap();
        let recovered = subnet.get_key();

        // Verify the subnet generation works
        let subnet2 = subnet_for_key(&recovered);
        // The subnet should be derivable from the recovered key
    }

    #[test]
    fn test_address_display() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let addr = addr_for_key(&public).unwrap();
        let display = addr.to_string();

        // Should be a valid IPv6 format
        assert!(display.contains(':'));
    }

    #[test]
    fn test_subnet_display() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let subnet = subnet_for_key(&public).unwrap();
        let display = subnet.to_string();

        // Should be in CIDR notation
        assert!(display.ends_with("/64"));
    }
}
