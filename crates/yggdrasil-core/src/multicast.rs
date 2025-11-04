use anyhow::Result;
use log::{debug, info, warn};
use std::net::{Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Multicast discovery
///
/// Used to automatically discover other Yggdrasil nodes on local network
pub struct Multicast {
    enabled: bool,
    interfaces: Vec<String>,
    interval: u64,
    multicast_addr: Ipv6Addr,
    multicast_port: u16,
    tx: Option<mpsc::Sender<SocketAddr>>,
}

impl Multicast {
    /// Create new multicast instance
    pub fn new(enabled: bool, interfaces: Vec<String>, interval: u64) -> Self {
        // Multicast address used by Yggdrasil
        let multicast_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x114);
        let multicast_port = 9001;

        let (tx, _rx) = mpsc::channel(256);

        Multicast {
            enabled,
            interfaces,
            interval,
            multicast_addr,
            multicast_port,
            tx: Some(tx),
        }
    }

    /// Start multicast discovery
    pub async fn start(&self) -> Result<()> {
        if !self.enabled {
            info!("Multicast discovery is disabled");
            return Ok(());
        }

        info!(
            "Starting multicast discovery (interval: {}s)",
            self.interval
        );
        info!(
            "Multicast address: {}:{}",
            self.multicast_addr, self.multicast_port
        );

        let multicast_addr = self.multicast_addr;
        let multicast_port = self.multicast_port;
        let interval = self.interval;
        let interfaces = self.interfaces.clone();

        // Start multicast listener task
        tokio::spawn(async move {
            if let Err(e) =
                Self::listen_multicast(multicast_addr, multicast_port, interfaces.clone()).await
            {
                warn!("Multicast listen error: {}", e);
            }
        });

        // Start multicast sender task
        tokio::spawn(async move {
            if let Err(e) = Self::send_multicast(multicast_addr, multicast_port, interval).await {
                warn!("Multicast send error: {}", e);
            }
        });

        info!("Multicast discovery started");
        Ok(())
    }

    /// Listen for multicast messages
    async fn listen_multicast(
        multicast_addr: Ipv6Addr,
        port: u16,
        _interfaces: Vec<String>,
    ) -> Result<()> {
        let bind_addr = format!("[::]:{}", port);

        match UdpSocket::bind(&bind_addr).await {
            Ok(socket) => {
                info!("Multicast listener bound to {}", bind_addr);

                // Join multicast group
                if let Err(e) = socket.join_multicast_v6(&multicast_addr, 0) {
                    warn!("Failed to join multicast group: {}", e);
                } else {
                    info!("Joined multicast group: {}", multicast_addr);
                }

                let mut buf = vec![0u8; 65535];

                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, addr)) => {
                            debug!("Received {} bytes from {}", len, addr);
                            // Parse announcement message and handle
                            // Actual implementation will verify message and attempt to connect to discovered nodes
                        }
                        Err(e) => {
                            warn!("Multicast receive error: {}", e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to bind multicast listener (may need elevated privileges): {}",
                    e
                );
                Ok(())
            }
        }
    }

    /// Send multicast announcement
    async fn send_multicast(multicast_addr: Ipv6Addr, port: u16, interval: u64) -> Result<()> {
        match UdpSocket::bind("[::]:0").await {
            Ok(socket) => {
                info!("Multicast sender created");

                let dest_addr = SocketAddr::new(multicast_addr.into(), port);

                loop {
                    // Construct announcement message (simplified version)
                    let announcement = b"YGGDRASIL_ANNOUNCE";

                    match socket.send_to(announcement, dest_addr).await {
                        Ok(_) => {
                            debug!("Sent multicast announcement to {}", dest_addr);
                        }
                        Err(e) => {
                            warn!("Failed to send multicast announcement: {}", e);
                        }
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                }
            }
            Err(e) => {
                warn!("Failed to create multicast sender: {}", e);
                Ok(())
            }
        }
    }

    /// Stop multicast discovery
    pub async fn stop(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        info!("Stopping multicast discovery");

        // Close channel
        self.tx = None;

        info!("Multicast discovery stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicast_creation() {
        let mc = Multicast::new(true, vec![".*".to_string()], 30);
        assert!(mc.enabled);
        assert_eq!(mc.interval, 30);
    }
}
