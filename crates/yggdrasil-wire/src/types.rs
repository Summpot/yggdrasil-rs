//! Wire packet types matching the Go implementation.

/// Wire packet type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WirePacketType {
    /// Unused/dummy packet
    Dummy = 0,
    /// Keep-alive packet
    KeepAlive = 1,
    /// Signature request for router protocol
    ProtoSigReq = 2,
    /// Signature response for router protocol
    ProtoSigRes = 3,
    /// Router announcement
    ProtoAnnounce = 4,
    /// Bloom filter update
    ProtoBloomFilter = 5,
    /// Path lookup request
    ProtoPathLookup = 6,
    /// Path notification
    ProtoPathNotify = 7,
    /// Path broken notification
    ProtoPathBroken = 8,
    /// Traffic packet
    Traffic = 9,
}

impl TryFrom<u8> for WirePacketType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Dummy),
            1 => Ok(Self::KeepAlive),
            2 => Ok(Self::ProtoSigReq),
            3 => Ok(Self::ProtoSigRes),
            4 => Ok(Self::ProtoAnnounce),
            5 => Ok(Self::ProtoBloomFilter),
            6 => Ok(Self::ProtoPathLookup),
            7 => Ok(Self::ProtoPathNotify),
            8 => Ok(Self::ProtoPathBroken),
            9 => Ok(Self::Traffic),
            _ => Err(()),
        }
    }
}

impl From<WirePacketType> for u8 {
    fn from(value: WirePacketType) -> Self {
        value as u8
    }
}

/// Session packet type identifiers for encrypted session layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionPacketType {
    /// Dummy/padding packet
    Dummy = 0,
    /// Session initialization
    Init = 1,
    /// Session acknowledgement
    Ack = 2,
    /// Encrypted traffic
    Traffic = 3,
}

impl TryFrom<u8> for SessionPacketType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Dummy),
            1 => Ok(Self::Init),
            2 => Ok(Self::Ack),
            3 => Ok(Self::Traffic),
            _ => Err(()),
        }
    }
}

impl From<SessionPacketType> for u8 {
    fn from(value: SessionPacketType) -> Self {
        value as u8
    }
}
