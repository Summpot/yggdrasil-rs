//! Wire protocol packet structures.
//!
//! This module defines the packet structures used in the wire protocol,
//! matching the Go implementation in ironwood/network.

use yggdrasil_types::{PeerPort, PublicKey, Signature, WireError, sizes::*};

use crate::encoding::*;
use crate::types::WirePacketType;

/// Router signature request.
/// Sent to request a signature from a peer for the routing protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterSigReq {
    /// Sequence number
    pub seq: u64,
    /// Random nonce to prevent replay
    pub nonce: u64,
}

impl RouterSigReq {
    /// Create a new signature request.
    pub fn new(seq: u64, nonce: u64) -> Self {
        Self { seq, nonce }
    }

    /// Get the bytes that should be signed.
    pub fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_KEY_SIZE * 2 + 16);
        out.extend_from_slice(node.as_bytes());
        out.extend_from_slice(parent.as_bytes());
        encode_varint(&mut out, self.seq);
        encode_varint(&mut out, self.nonce);
        out
    }
}

impl WireEncode for RouterSigReq {
    fn wire_size(&self) -> usize {
        varint_size(self.seq) + varint_size(self.nonce)
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        encode_varint(out, self.seq);
        encode_varint(out, self.nonce);
        Ok(())
    }
}

impl WireDecode for RouterSigReq {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let seq = chop_varint(data).ok_or(WireError::Decode)?;
        let nonce = chop_varint(data).ok_or(WireError::Decode)?;
        Ok(Self { seq, nonce })
    }
}

/// Router signature response.
/// Response to a signature request, includes the port assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterSigRes {
    /// The request this is responding to
    pub req: RouterSigReq,
    /// Assigned port number
    pub port: PeerPort,
    /// Parent's signature
    pub psig: Signature,
}

impl RouterSigRes {
    /// Check if this response is valid for the given node and parent.
    pub fn check(&self, node: &PublicKey, parent: &PublicKey) -> bool {
        let msg = self.bytes_for_sig(node, parent);
        parent.verify(&msg, &self.psig)
    }

    /// Get the bytes that should be signed (includes port).
    pub fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
        let mut out = self.req.bytes_for_sig(node, parent);
        encode_varint(&mut out, self.port);
        out
    }
}

impl WireEncode for RouterSigRes {
    fn wire_size(&self) -> usize {
        self.req.wire_size() + varint_size(self.port) + SIGNATURE_SIZE
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        self.req.wire_encode(out)?;
        encode_varint(out, self.port);
        out.extend_from_slice(self.psig.as_bytes());
        Ok(())
    }
}

impl WireDecode for RouterSigRes {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let req = RouterSigReq::wire_decode(data)?;
        let port = chop_varint(data).ok_or(WireError::Decode)?;
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        if !chop_slice(&mut sig_bytes, data) {
            return Err(WireError::Decode);
        }
        let psig = Signature::from(sig_bytes);
        Ok(Self { req, port, psig })
    }
}

/// Router announcement.
/// Announces routing information to peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAnnounce {
    /// Public key of the announcing node
    pub key: PublicKey,
    /// Parent node's public key
    pub parent: PublicKey,
    /// Signature response data
    pub sig_res: RouterSigRes,
    /// Node's signature
    pub sig: Signature,
}

impl RouterAnnounce {
    /// Check if this announcement is valid.
    pub fn check(&self) -> bool {
        // Port 0 is only valid for self-rooted nodes
        if self.sig_res.port == 0 && self.key != self.parent {
            return false;
        }

        let msg = self.sig_res.bytes_for_sig(&self.key, &self.parent);

        // Verify both signatures
        self.key.verify(&msg, &self.sig) && self.parent.verify(&msg, &self.sig_res.psig)
    }
}

impl WireEncode for RouterAnnounce {
    fn wire_size(&self) -> usize {
        PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + self.sig_res.wire_size() + SIGNATURE_SIZE
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(self.parent.as_bytes());
        self.sig_res.wire_encode(out)?;
        out.extend_from_slice(self.sig.as_bytes());
        Ok(())
    }
}

impl WireDecode for RouterAnnounce {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut key_bytes, data) {
            return Err(WireError::Decode);
        }
        let key = PublicKey::from(key_bytes);

        let mut parent_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut parent_bytes, data) {
            return Err(WireError::Decode);
        }
        let parent = PublicKey::from(parent_bytes);

        let sig_res = RouterSigRes::wire_decode(data)?;

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        if !chop_slice(&mut sig_bytes, data) {
            return Err(WireError::Decode);
        }
        let sig = Signature::from(sig_bytes);

        Ok(Self {
            key,
            parent,
            sig_res,
            sig,
        })
    }
}

/// Traffic packet for routing actual data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traffic {
    /// Path through the network (peer ports)
    pub path: Vec<PeerPort>,
    /// Return path from source
    pub from: Vec<PeerPort>,
    /// Source node's public key
    pub source: PublicKey,
    /// Destination node's public key
    pub dest: PublicKey,
    /// Watermark for loop prevention
    pub watermark: u64,
    /// Payload data
    pub payload: Vec<u8>,
}

impl Traffic {
    /// Create a new traffic packet.
    pub fn new(source: PublicKey, dest: PublicKey, payload: Vec<u8>) -> Self {
        Self {
            path: Vec::new(),
            from: Vec::new(),
            source,
            dest,
            watermark: u64::MAX,
            payload,
        }
    }

    /// Copy data from another traffic packet (reusing allocations).
    pub fn copy_from(&mut self, other: &Traffic) {
        self.path.clear();
        self.path.extend_from_slice(&other.path);
        self.from.clear();
        self.from.extend_from_slice(&other.from);
        self.source = other.source;
        self.dest = other.dest;
        self.watermark = other.watermark;
        self.payload.clear();
        self.payload.extend_from_slice(&other.payload);
    }

    /// Get the wire packet type for this packet.
    pub fn wire_type() -> WirePacketType {
        WirePacketType::Traffic
    }
}

impl WireEncode for Traffic {
    fn wire_size(&self) -> usize {
        path_size(&self.path)
            + path_size(&self.from)
            + PUBLIC_KEY_SIZE
            + PUBLIC_KEY_SIZE
            + varint_size(self.watermark)
            + self.payload.len()
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        encode_path(out, &self.path);
        encode_path(out, &self.from);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        encode_varint(out, self.watermark);
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl WireDecode for Traffic {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let path = chop_path(data).ok_or(WireError::Decode)?;
        let from = chop_path(data).ok_or(WireError::Decode)?;

        let mut source_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut source_bytes, data) {
            return Err(WireError::Decode);
        }
        let source = PublicKey::from(source_bytes);

        let mut dest_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut dest_bytes, data) {
            return Err(WireError::Decode);
        }
        let dest = PublicKey::from(dest_bytes);

        let watermark = chop_varint(data).ok_or(WireError::Decode)?;

        // Remaining data is the payload
        let payload = data.to_vec();
        *data = &[];

        Ok(Self {
            path,
            from,
            source,
            dest,
            watermark,
            payload,
        })
    }
}

/// Path lookup request for finding routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLookup {
    /// Source node requesting the lookup
    pub source: PublicKey,
    /// Destination being looked up
    pub dest: PublicKey,
    /// Path from source (for response routing)
    pub from: Vec<PeerPort>,
}

impl PathLookup {
    /// Get the wire packet type for this packet.
    pub fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathLookup
    }
}

impl WireEncode for PathLookup {
    fn wire_size(&self) -> usize {
        PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + path_size(&self.from)
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        encode_path(out, &self.from);
        Ok(())
    }
}

impl WireDecode for PathLookup {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let mut source_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut source_bytes, data) {
            return Err(WireError::Decode);
        }
        let source = PublicKey::from(source_bytes);

        let mut dest_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut dest_bytes, data) {
            return Err(WireError::Decode);
        }
        let dest = PublicKey::from(dest_bytes);

        let from = chop_path(data).ok_or(WireError::Decode)?;

        if !data.is_empty() {
            return Err(WireError::Decode);
        }

        Ok(Self { source, dest, from })
    }
}

/// Path notify info (signed by source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotifyInfo {
    /// Sequence number
    pub seq: u64,
    /// Path from root to source (coords)
    pub path: Vec<PeerPort>,
    /// Signature from the source key
    pub sig: Signature,
}

impl PathNotifyInfo {
    /// Check if two PathNotifyInfo are equal (ignoring signature).
    pub fn content_eq(&self, other: &Self) -> bool {
        self.seq == other.seq && self.path == other.path
    }

    /// Get the bytes that should be signed.
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(&mut out, self.seq);
        encode_path(&mut out, &self.path);
        out
    }

    /// Sign this info with the given private key.
    pub fn sign(&mut self, key: &yggdrasil_types::PrivateKey) {
        let msg = self.bytes_for_sig();
        self.sig = key.sign(&msg);
    }

    /// Verify the signature with the given public key.
    pub fn verify(&self, key: &PublicKey) -> bool {
        let msg = self.bytes_for_sig();
        key.verify(&msg, &self.sig)
    }
}

impl WireEncode for PathNotifyInfo {
    fn wire_size(&self) -> usize {
        varint_size(self.seq) + path_size(&self.path) + SIGNATURE_SIZE
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        encode_varint(out, self.seq);
        encode_path(out, &self.path);
        out.extend_from_slice(self.sig.as_bytes());
        Ok(())
    }
}

impl WireDecode for PathNotifyInfo {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let seq = chop_varint(data).ok_or(WireError::Decode)?;
        let path = chop_path(data).ok_or(WireError::Decode)?;

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        if !chop_slice(&mut sig_bytes, data) {
            return Err(WireError::Decode);
        }
        let sig = Signature::from(sig_bytes);

        if !data.is_empty() {
            return Err(WireError::Decode);
        }

        Ok(Self { seq, path, sig })
    }
}

/// Path notification with routing info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotify {
    /// Path to route this notification
    pub path: Vec<PeerPort>,
    /// Watermark for loop prevention
    pub watermark: u64,
    /// Source of the notification
    pub source: PublicKey,
    /// Destination for the notification
    pub dest: PublicKey,
    /// Signed path info
    pub info: PathNotifyInfo,
}

impl PathNotify {
    /// Verify the notification signature.
    pub fn check(&self) -> bool {
        self.info.verify(&self.source)
    }

    /// Get the wire packet type for this packet.
    pub fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathNotify
    }
}

impl WireEncode for PathNotify {
    fn wire_size(&self) -> usize {
        path_size(&self.path)
            + varint_size(self.watermark)
            + PUBLIC_KEY_SIZE
            + PUBLIC_KEY_SIZE
            + self.info.wire_size()
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        encode_path(out, &self.path);
        encode_varint(out, self.watermark);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        self.info.wire_encode(out)?;
        Ok(())
    }
}

impl WireDecode for PathNotify {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let path = chop_path(data).ok_or(WireError::Decode)?;
        let watermark = chop_varint(data).ok_or(WireError::Decode)?;

        let mut source_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut source_bytes, data) {
            return Err(WireError::Decode);
        }
        let source = PublicKey::from(source_bytes);

        let mut dest_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut dest_bytes, data) {
            return Err(WireError::Decode);
        }
        let dest = PublicKey::from(dest_bytes);

        let info = PathNotifyInfo::wire_decode(data)?;

        Ok(Self {
            path,
            watermark,
            source,
            dest,
            info,
        })
    }
}

/// Path broken notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBroken {
    /// Path to route this notification
    pub path: Vec<PeerPort>,
    /// Watermark for loop prevention
    pub watermark: u64,
    /// Source of the notification
    pub source: PublicKey,
    /// Destination for the notification
    pub dest: PublicKey,
}

impl PathBroken {
    /// Get the wire packet type for this packet.
    pub fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathBroken
    }
}

impl WireEncode for PathBroken {
    fn wire_size(&self) -> usize {
        path_size(&self.path) + varint_size(self.watermark) + PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE
    }

    fn wire_encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        encode_path(out, &self.path);
        encode_varint(out, self.watermark);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        Ok(())
    }
}

impl WireDecode for PathBroken {
    fn wire_decode(data: &mut &[u8]) -> Result<Self, WireError> {
        let path = chop_path(data).ok_or(WireError::Decode)?;
        let watermark = chop_varint(data).ok_or(WireError::Decode)?;

        let mut source_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut source_bytes, data) {
            return Err(WireError::Decode);
        }
        let source = PublicKey::from(source_bytes);

        let mut dest_bytes = [0u8; PUBLIC_KEY_SIZE];
        if !chop_slice(&mut dest_bytes, data) {
            return Err(WireError::Decode);
        }
        let dest = PublicKey::from(dest_bytes);

        if !data.is_empty() {
            return Err(WireError::Decode);
        }

        Ok(Self {
            path,
            watermark,
            source,
            dest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yggdrasil_types::PrivateKey;

    #[test]
    fn test_router_sig_req_roundtrip() {
        let req = RouterSigReq::new(123, 456);

        let mut buf = Vec::new();
        req.wire_encode(&mut buf).unwrap();
        assert_eq!(buf.len(), req.wire_size());

        let mut data = buf.as_slice();
        let decoded = RouterSigReq::wire_decode(&mut data).unwrap();
        assert_eq!(decoded, req);
        assert!(data.is_empty());
    }

    #[test]
    fn test_traffic_roundtrip() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let traffic = Traffic {
            path: vec![1, 2, 3],
            from: vec![4, 5],
            source: public,
            dest: public,
            watermark: u64::MAX,
            payload: b"Hello, World!".to_vec(),
        };

        let mut buf = Vec::new();
        traffic.wire_encode(&mut buf).unwrap();
        assert_eq!(buf.len(), traffic.wire_size());

        let mut data = buf.as_slice();
        let decoded = Traffic::wire_decode(&mut data).unwrap();
        assert_eq!(decoded, traffic);
        assert!(data.is_empty());
    }

    #[test]
    fn test_path_lookup_roundtrip() {
        let private = PrivateKey::generate();
        let public = private.public_key();

        let lookup = PathLookup {
            source: public,
            dest: public,
            from: vec![1, 2, 3],
        };

        let mut buf = Vec::new();
        lookup.wire_encode(&mut buf).unwrap();
        assert_eq!(buf.len(), lookup.wire_size());

        let mut data = buf.as_slice();
        let decoded = PathLookup::wire_decode(&mut data).unwrap();
        assert_eq!(decoded, lookup);
        assert!(data.is_empty());
    }
}
