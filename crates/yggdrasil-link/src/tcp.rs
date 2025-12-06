//! TCP link implementation.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use yggdrasil_types::PublicKey;

use crate::link::{Link, LinkConfig, LinkError, LinkInfo};

/// A TCP link.
pub struct TcpLink {
    info: LinkInfo,
    stream: Mutex<TcpStream>,
    connected: AtomicBool,
    config: LinkConfig,
}

impl TcpLink {
    /// Create a new TCP link from an established connection.
    pub fn new(
        stream: TcpStream,
        remote_key: PublicKey,
        outbound: bool,
        config: LinkConfig,
    ) -> Result<Self, LinkError> {
        let remote_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;

        Ok(Self {
            info: LinkInfo {
                remote_key,
                remote_addr,
                local_addr,
                link_type: "tcp".to_string(),
                outbound,
                established: Instant::now(),
            },
            stream: Mutex::new(stream),
            connected: AtomicBool::new(true),
            config,
        })
    }

    /// Connect to a remote address.
    pub async fn connect(
        addr: SocketAddr,
        remote_key: PublicKey,
        config: LinkConfig,
    ) -> Result<Self, LinkError> {
        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| LinkError::Timeout)?
            .map_err(LinkError::Io)?;

        Self::new(stream, remote_key, true, config)
    }
}

#[async_trait]
impl Link for TcpLink {
    fn info(&self) -> &LinkInfo {
        &self.info
    }

    async fn send(&self, data: &[u8]) -> Result<(), LinkError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkError::Closed);
        }

        if data.len() > self.config.max_message_size {
            return Err(LinkError::MessageTooLarge {
                size: data.len(),
                max: self.config.max_message_size,
            });
        }

        let mut stream = self.stream.lock().await;

        // Write length prefix (2 bytes, big endian)
        let len = data.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, LinkError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkError::Closed);
        }

        let mut stream = self.stream.lock().await;

        // Read length prefix
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;

        if len > self.config.max_message_size {
            return Err(LinkError::MessageTooLarge {
                size: len,
                max: self.config.max_message_size,
            });
        }

        // Read message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        Ok(buf)
    }

    async fn close(&self) -> Result<(), LinkError> {
        self.connected.store(false, Ordering::Release);
        let mut stream = self.stream.lock().await;
        stream.shutdown().await?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}
