use std::net::Ipv6Addr;
use ed25519_dalek::VerifyingKey;

/// Yggdrasil address structure
/// 
/// Yggdrasil uses IPv6 addresses with prefix 0x02 or 0x03
/// Address is derived from public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(Ipv6Addr);

impl Address {
    /// Generate Yggdrasil address from public key
    /// 
    /// This implements the same algorithm as the Go version:
    /// 1. Start with prefix 0x02 (node addresses have last bit = 0)
    /// 2. Count leading 1s in bitwise inverse of public key
    /// 3. Store count in next byte
    /// 4. Append remaining bits (after leading 1s and first 0)
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let key_bytes = public_key.to_bytes();
        
        // Bitwise inverse of the public key
        let mut buf = [0u8; 32];
        for (i, &b) in key_bytes.iter().enumerate() {
            buf[i] = !b;
        }
        
        // Count leading 1s in the inverted key
        let mut ones = 0u8;
        let mut done = false;
        let mut temp = Vec::with_capacity(32);
        let mut bits = 0u8;
        let mut n_bits = 0u8;
        
        for idx in 0..(8 * buf.len()) {
            let bit = (buf[idx / 8] & (0x80 >> (idx % 8))) >> (7 - (idx % 8));
            
            if !done && bit != 0 {
                ones += 1;
                continue;
            }
            if !done && bit == 0 {
                done = true;
                continue; // Skip the first 0 bit
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
        let mut addr_bytes = [0u8; 16];
        let prefix = 0x02u8; // Nodes use 0x02, subnets use 0x03
        addr_bytes[0] = prefix;
        addr_bytes[1] = ones; // Number of leading 1s
        
        // Copy remaining bits
        let copy_len = (addr_bytes.len() - 2).min(temp.len());
        addr_bytes[2..2 + copy_len].copy_from_slice(&temp[..copy_len]);
        
        Address(Ipv6Addr::from(addr_bytes))
    }
    
    /// Create address from byte array
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Address(Ipv6Addr::from(bytes))
    }
    
    /// Get IPv6 address
    pub fn as_ipv6(&self) -> Ipv6Addr {
        self.0
    }
    
    /// Get address byte array
    pub fn as_bytes(&self) -> [u8; 16] {
        self.0.octets()
    }
    
    /// Check if this is a valid Yggdrasil address
    pub fn is_valid(&self) -> bool {
        let bytes = self.0.octets();
        // Check if first byte is 0x02 or 0x03
        bytes[0] == 0x02 || bytes[0] == 0x03
    }
}

impl From<Ipv6Addr> for Address {
    fn from(addr: Ipv6Addr) -> Self {
        Address(addr)
    }
}

impl From<Address> for Ipv6Addr {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Subnet address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Subnet {
    addr: Ipv6Addr,
    prefix_len: u8,
}

impl Subnet {
    /// Generate subnet address from public key
    /// 
    /// Same as Address but with prefix 0x03 (last bit = 1 for subnets)
    /// Only first 64 bits are used, rest are zero
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let key_bytes = public_key.to_bytes();
        
        // Bitwise inverse of the public key
        let mut buf = [0u8; 32];
        for (i, &b) in key_bytes.iter().enumerate() {
            buf[i] = !b;
        }
        
        // Count leading 1s in the inverted key
        let mut ones = 0u8;
        let mut done = false;
        let mut temp = Vec::with_capacity(32);
        let mut bits = 0u8;
        let mut n_bits = 0u8;
        
        for idx in 0..(8 * buf.len()) {
            let bit = (buf[idx / 8] & (0x80 >> (idx % 8))) >> (7 - (idx % 8));
            
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
        
        // Build the subnet address (only first 8 bytes for /64, rest are zero)
        let mut addr_bytes = [0u8; 16];
        let prefix = 0x03u8; // Subnets use 0x03 (last bit = 1)
        addr_bytes[0] = prefix;
        addr_bytes[1] = ones;
        
        // Copy remaining bits only for the first 8 bytes (64 bits total)
        let copy_len = (8 - 2).min(temp.len()); // Only 6 more bytes after prefix and ones
        addr_bytes[2..2 + copy_len].copy_from_slice(&temp[..copy_len]);
        // Bytes 8-15 remain zero (this is the /64 subnet, host part is zero)
        
        Subnet {
            addr: Ipv6Addr::from(addr_bytes),
            prefix_len: 64,
        }
    }
    
    /// Get address
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }
    
    /// Get prefix length
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    
    #[test]
    fn test_address_from_public_key() {
        // Use fixed key instead of random generation
        let secret = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();
        
        let addr = Address::from_public_key(&public_key);
        assert!(addr.is_valid());
    }
    
    #[test]
    fn test_subnet_from_public_key() {
        // Use fixed key instead of random generation
        let secret = [2u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();
        
        let subnet = Subnet::from_public_key(&public_key);
        assert_eq!(subnet.prefix_len(), 64);
    }
    
    /// Test address derivation compatibility with Go implementation
    /// 
    /// These test vectors were generated using Yggdrasil-Go and verified
    /// to produce identical results in Rust implementation.
    #[test]
    fn test_go_compatibility_addresses() {
        // Test case: verified with Go implementation
        let key_hex = "a3fa855aa6f644e1c7cd3151b0885ca7e95457b9d3b53bfdfac61207ce14abd6";
        let key_bytes = hex::decode(key_hex).expect("valid hex");
        let signing_key = SigningKey::from_bytes(key_bytes.as_slice().try_into().unwrap());
        let public_key = signing_key.verifying_key();
        
        let addr = Address::from_public_key(&public_key);
        let subnet = Subnet::from_public_key(&public_key);
        
        // Expected values from Go implementation
        assert_eq!(addr.to_string(), "200:38d2:ba68:4c54:7845:b793:e028:9593");
        assert_eq!(subnet.to_string(), "300:38d2:ba68:4c54::/64");
    }
    
    /// Test multiple random keys to ensure consistent derivation
    #[test]
    fn test_go_compatibility_multiple_keys() {
        // Test vectors: (private_key_seed_hex, expected_address, expected_subnet)
        // All vectors verified against Go implementation
        let test_cases = vec![
            (
                "dc26f2d22f6a4e62b619ea4dcfe876ffd6d0f459450b42bfdaa27883981cb455",
                "202:70cf:883e:e735:665b:36c5:4ab4:495e",
                "302:70cf:883e:e735::/64"
            ),
            (
                "aa19891793a1ea6e382f4656f990bee00d8db1bef463fa1b47de2a8c154add8e",
                "200:f20d:11a6:776e:776e:c803:ba6f:a7c3",
                "300:f20d:11a6:776e::/64"
            ),
            (
                "77bf26bd978d7fc3daf26337a1207e5818672183797a1b4ad10c6abf2e273cda",
                "202:e505:e42c:694a:e274:c319:a15e:a769",
                "302:e505:e42c:694a::/64"
            ),
        ];
        
        for (seed_hex, expected_addr, expected_subnet) in test_cases {
            let seed_bytes = hex::decode(seed_hex).expect("valid hex");
            let signing_key = SigningKey::from_bytes(seed_bytes.as_slice().try_into().unwrap());
            let public_key = signing_key.verifying_key();
            
            let addr = Address::from_public_key(&public_key);
            let subnet = Subnet::from_public_key(&public_key);
            
            assert_eq!(
                addr.to_string(), 
                expected_addr,
                "Address mismatch for seed {}", 
                seed_hex
            );
            assert_eq!(
                subnet.to_string(), 
                expected_subnet,
                "Subnet mismatch for seed {}",
                seed_hex
            );
        }
    }
    
    /// Test that subnet only uses first 64 bits (network prefix)
    #[test]
    fn test_subnet_format() {
        let secret = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();
        
        let subnet = Subnet::from_public_key(&public_key);
        let subnet_str = subnet.to_string();
        
        // Subnet should end with ::/64
        assert!(subnet_str.ends_with("::/64"), "Subnet should have zero host bits: {}", subnet_str);
        
        // Get the address and verify last 64 bits are zero
        let addr_segments = subnet.addr().segments();
        // Last 4 segments (64 bits) should be zero
        assert_eq!(addr_segments[4], 0, "Subnet host bits should be zero");
        assert_eq!(addr_segments[5], 0, "Subnet host bits should be zero");
        assert_eq!(addr_segments[6], 0, "Subnet host bits should be zero");
        assert_eq!(addr_segments[7], 0, "Subnet host bits should be zero");
    }
}
