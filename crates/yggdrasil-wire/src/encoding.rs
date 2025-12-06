//! Wire protocol encoding utilities.
//!
//! This module provides functions for encoding and decoding wire protocol
//! primitives, matching the Go implementation exactly.

use yggdrasil_types::{PeerPort, WireError};

/// Calculate the size needed to encode a varint.
#[inline]
pub fn varint_size(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let bits = 64 - value.leading_zeros() as usize;
    (bits + 6) / 7 // Ceiling division by 7
}

/// Encode a u64 as a varint, appending to the output buffer.
/// Returns the number of bytes written.
pub fn encode_varint(out: &mut Vec<u8>, mut value: u64) -> usize {
    let start = out.len();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out.len() - start
}

/// Decode a varint from the input slice.
/// Returns the decoded value and the number of bytes consumed.
pub fn decode_varint(data: &[u8]) -> Result<(u64, usize), WireError> {
    let mut value: u64 = 0;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if shift > 63 {
            return Err(WireError::Decode);
        }

        value |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }

        shift += 7;
    }

    Err(WireError::Decode)
}

/// Chop (extract) a slice of fixed size from the data.
/// Modifies the data slice to point to the remaining data.
pub fn chop_slice<'a>(out: &mut [u8], data: &mut &'a [u8]) -> bool {
    if data.len() < out.len() {
        return false;
    }
    out.copy_from_slice(&data[..out.len()]);
    *data = &data[out.len()..];
    true
}

/// Chop (extract) a variable-length slice from the data.
/// The size parameter determines how many bytes to extract.
pub fn chop_bytes<'a>(data: &mut &'a [u8], size: usize) -> Option<&'a [u8]> {
    if data.len() < size {
        return None;
    }
    let (out, rest) = data.split_at(size);
    *data = rest;
    Some(out)
}

/// Chop (extract) a varint from the data.
pub fn chop_varint(data: &mut &[u8]) -> Option<u64> {
    let (value, len) = decode_varint(data).ok()?;
    *data = &data[len..];
    Some(value)
}

/// Calculate the size needed to encode a path (slice of peer ports).
pub fn path_size(path: &[PeerPort]) -> usize {
    let mut size = 0;
    for &port in path {
        size += varint_size(port);
    }
    size += varint_size(0); // Zero terminator
    size
}

/// Encode a path (slice of peer ports), appending to the output buffer.
pub fn encode_path(out: &mut Vec<u8>, path: &[PeerPort]) {
    for &port in path {
        encode_varint(out, port);
    }
    encode_varint(out, 0); // Zero terminator
}

/// Decode a path from the input data.
/// Returns the path and the number of bytes consumed.
pub fn decode_path(data: &[u8]) -> Result<(Vec<PeerPort>, usize), WireError> {
    let mut path = Vec::new();
    let mut remaining = data;

    loop {
        let value = chop_varint(&mut remaining).ok_or(WireError::Decode)?;
        if value == 0 {
            break;
        }
        path.push(value);
    }

    let consumed = data.len() - remaining.len();
    Ok((path, consumed))
}

/// Chop (extract) a path from the data.
pub fn chop_path(data: &mut &[u8]) -> Option<Vec<PeerPort>> {
    let mut path = Vec::new();

    loop {
        let value = chop_varint(data)?;
        if value == 0 {
            break;
        }
        path.push(value);
    }

    Some(path)
}

/// Trait for types that can be encoded to the wire format.
pub trait WireEncode {
    /// Calculate the size of the encoded representation.
    fn wire_size(&self) -> usize;

    /// Encode to the wire format, appending to the output buffer.
    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError>;
}

/// Trait for types that can be decoded from the wire format.
pub trait WireDecode: Sized {
    /// Decode from the wire format.
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX];

        for &value in &test_values {
            let mut buf = Vec::new();
            let written = encode_varint(&mut buf, value);
            assert_eq!(written, varint_size(value));

            let (decoded, consumed) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, written);
        }
    }

    #[test]
    fn test_path_roundtrip() {
        let paths: &[&[PeerPort]] = &[&[], &[1], &[1, 2, 3], &[1, 127, 128, 16383, 16384]];

        for &path in paths {
            let mut buf = Vec::new();
            encode_path(&mut buf, path);
            assert_eq!(buf.len(), path_size(path));

            let (decoded, consumed) = decode_path(&buf).unwrap();
            assert_eq!(decoded, path);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_chop_slice() {
        let data = [1u8, 2, 3, 4, 5];
        let mut remaining = data.as_slice();
        let mut out = [0u8; 3];

        assert!(chop_slice(&mut out, &mut remaining));
        assert_eq!(out, [1, 2, 3]);
        assert_eq!(remaining, &[4, 5]);

        // Try to chop more than available
        let mut out2 = [0u8; 5];
        assert!(!chop_slice(&mut out2, &mut remaining));
    }

    #[test]
    fn test_chop_bytes() {
        let data = [1u8, 2, 3, 4, 5];
        let mut remaining = data.as_slice();

        let bytes = chop_bytes(&mut remaining, 3).unwrap();
        assert_eq!(bytes, &[1, 2, 3]);
        assert_eq!(remaining, &[4, 5]);

        // Try to chop more than available
        assert!(chop_bytes(&mut remaining, 5).is_none());
    }
}
