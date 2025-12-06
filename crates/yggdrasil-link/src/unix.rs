//! Unix socket link implementation.
//!
//! This module provides link implementation over Unix domain sockets.

#[cfg(unix)]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_trait::async_trait;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use yggdrasil_types::PublicKey;

use crate::link::{Link, LinkConfig, LinkError, LinkInfo};

/// A Unix socket link (only available on Unix platforms).
#[cfg(unix)]
pub struct UnixLink {
    info: LinkInfo,
    stream: Mutex<UnixStream>,
    connected: AtomicBool,
    config: LinkConfig,
}

#[cfg(unix)]
impl UnixLink {
    /// Create a new Unix socket link from an established connection.
    pub fn new(
        stream: UnixStream,
        remote_key: PublicKey,
        outbound: bool,
        config: LinkConfig,
    ) -> Self {
        // Unix sockets don't have traditional addresses, use placeholder
        let placeholder_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0);

        Self {
            info: LinkInfo {
                remote_key,
                remote_addr: placeholder_addr,
                local_addr: placeholder_addr,
                link_type: "unix".to_string(),
                outbound,
                established: Instant::now(),
            },
            stream: Mutex::new(stream),
            connected: AtomicBool::new(true),
            config,
        }
    }

    /// Connect to a Unix socket.
    pub async fn connect<P: AsRef<Path>>(
        path: P,
        remote_key: PublicKey,
        config: LinkConfig,
    ) -> Result<Self, LinkError> {
        let stream = tokio::time::timeout(config.timeout, UnixStream::connect(path.as_ref()))
            .await
            .map_err(|_| LinkError::Timeout)?
            .map_err(LinkError::Io)?;

        Ok(Self::new(stream, remote_key, true, config))
    }
}

#[cfg(unix)]
#[async_trait]
impl Link for UnixLink {
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

// Provide a stub implementation for non-Unix platforms
#[cfg(not(unix))]
pub struct UnixLink {
    _private: (),
}

#[cfg(not(unix))]
impl UnixLink {
    /// Unix sockets are not available on this platform.
    pub fn new(_stream: (), _remote_key: PublicKey, _outbound: bool, _config: LinkConfig) -> Self {
        panic!("Unix sockets are not available on this platform")
    }
}
