//! Wire protocol framing.
//!
//! Implements length-prefixed framing matching the Go implementation:
//! - Outgoing: varint(payload_len) + packet_type + payload
//! - Incoming: read varint length, then read exact bytes

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::encoding::{encode_varint, varint_size};
use crate::types::WirePacketType;
use yggdrasil_types::WireError;

/// Maximum message size (64KB by default, matching Go).
pub const MAX_MESSAGE_SIZE: u64 = 64 * 1024;

/// A framed packet with its type and payload.
#[derive(Debug, Clone)]
pub struct FramedPacket {
    /// The packet type.
    pub packet_type: WirePacketType,
    /// The payload (excluding the packet type byte).
    pub payload: Vec<u8>,
}

impl FramedPacket {
    /// Create a new framed packet.
    pub fn new(packet_type: WirePacketType, payload: Vec<u8>) -> Self {
        Self {
            packet_type,
            payload,
        }
    }
}

/// Read a single framed packet from a stream.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FramedPacket, WireError> {
    // Read the length prefix (varint)
    let length = read_varint(reader).await?;

    if length == 0 {
        return Err(WireError::Decode);
    }

    if length > MAX_MESSAGE_SIZE {
        return Err(WireError::Decode);
    }

    // Read the full message
    let mut buf = vec![0u8; length as usize];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|_| WireError::Decode)?;

    // First byte is the packet type
    let packet_type_byte = buf[0];
    let packet_type = WirePacketType::try_from(packet_type_byte).map_err(|_| WireError::Decode)?;

    // Rest is the payload
    let payload = buf[1..].to_vec();

    Ok(FramedPacket {
        packet_type,
        payload,
    })
}

/// Write a framed packet to a stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &FramedPacket,
) -> Result<(), WireError> {
    // Calculate the message size (packet type byte + payload)
    let message_size = 1 + packet.payload.len();

    // Build the frame: length prefix + packet type + payload
    let mut frame = Vec::with_capacity(varint_size(message_size as u64) + message_size);
    encode_varint(&mut frame, message_size as u64);
    frame.push(packet.packet_type.into());
    frame.extend_from_slice(&packet.payload);

    writer
        .write_all(&frame)
        .await
        .map_err(|_| WireError::Encode)?;

    Ok(())
}

/// Write a framed packet with pre-encoded payload.
pub async fn write_frame_with_payload<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet_type: WirePacketType,
    payload: &[u8],
) -> Result<(), WireError> {
    // Calculate the message size (packet type byte + payload)
    let message_size = 1 + payload.len();

    // Build the frame: length prefix + packet type + payload
    let mut frame = Vec::with_capacity(varint_size(message_size as u64) + message_size);
    encode_varint(&mut frame, message_size as u64);
    frame.push(packet_type.into());
    frame.extend_from_slice(payload);

    writer
        .write_all(&frame)
        .await
        .map_err(|_| WireError::Encode)?;

    Ok(())
}

/// Read a varint from a stream.
async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u64, WireError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;

    loop {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|_| WireError::Decode)?;

        let b = byte[0];

        if shift >= 64 {
            return Err(WireError::Decode);
        }

        value |= ((b & 0x7F) as u64) << shift;

        if b & 0x80 == 0 {
            return Ok(value);
        }

        shift += 7;
    }
}

/// Flush the writer.
pub async fn flush_writer<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<(), WireError> {
    writer.flush().await.map_err(|_| WireError::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let packet = FramedPacket::new(WirePacketType::KeepAlive, vec![1, 2, 3, 4, 5]);

        // Write the frame
        let mut buf = Vec::new();
        let mut writer = Cursor::new(&mut buf);
        write_frame(&mut writer, &packet).await.unwrap();

        // Read it back
        let mut reader = Cursor::new(&buf);
        let decoded = read_frame(&mut reader).await.unwrap();

        assert_eq!(decoded.packet_type, packet.packet_type);
        assert_eq!(decoded.payload, packet.payload);
    }

    #[tokio::test]
    async fn test_read_varint() {
        // Test single byte varints
        let mut reader = Cursor::new(vec![0x00]);
        assert_eq!(read_varint(&mut reader).await.unwrap(), 0);

        let mut reader = Cursor::new(vec![0x7F]);
        assert_eq!(read_varint(&mut reader).await.unwrap(), 127);

        // Test two byte varints
        let mut reader = Cursor::new(vec![0x80, 0x01]);
        assert_eq!(read_varint(&mut reader).await.unwrap(), 128);

        let mut reader = Cursor::new(vec![0xFF, 0x01]);
        assert_eq!(read_varint(&mut reader).await.unwrap(), 255);
    }
}
