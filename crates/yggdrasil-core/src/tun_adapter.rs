use anyhow::Result;
use log::{info, warn, debug, error};
use tokio::sync::mpsc;
use std::sync::Arc;

/// TUN packet event
#[derive(Debug, Clone)]
pub enum TunEvent {
    /// Packet read from TUN interface
    PacketRead(Vec<u8>),
    /// TUN device error
    Error(String),
}

/// TUN adapter
/// 
/// Manages TUN/TAP virtual network interface
pub struct TunAdapter {
    name: String,
    mtu: u32,
    tx: mpsc::Sender<Vec<u8>>,
    event_tx: mpsc::Sender<TunEvent>,
    #[cfg(target_os = "linux")]
    device: Option<Arc<std::sync::Mutex<tun::Device>>>,
}

impl TunAdapter {
    /// Create new TUN adapter
    pub fn new(name: String, mtu: u32) -> (Self, mpsc::Receiver<Vec<u8>>, mpsc::Receiver<TunEvent>) {
        info!("Creating TUN adapter: {} (MTU: {})", name, mtu);
        
        let (tx, rx) = mpsc::channel(1024);
        let (event_tx, event_rx) = mpsc::channel(1024);
        
        #[cfg(target_os = "linux")]
        let device = {
            let mut config = tun::Configuration::default();
            config.tun_name(&name)
                  .mtu(mtu as u16)
                  .up();
            
            match tun::create(&config) {
                Ok(dev) => {
                    info!("TUN device created successfully: {}", name);
                    Some(Arc::new(std::sync::Mutex::new(dev)))
                }
                Err(e) => {
                    warn!("Failed to create TUN device (may need root privileges): {}", e);
                    warn!("Continuing without TUN device...");
                    None
                }
            }
        };
        
        let adapter = TunAdapter {
            name,
            mtu,
            tx,
            event_tx,
            #[cfg(target_os = "linux")]
            device,
        };
        
        (adapter, rx, event_rx)
    }
    
    /// Start TUN adapter
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting TUN adapter: {}", self.name);
        
        #[cfg(target_os = "linux")]
        if let Some(device) = &self.device {
            let device_clone = Arc::clone(device);
            let event_tx = self.event_tx.clone();
            let name = self.name.clone();
            let mtu = self.mtu;
            
            // Start read loop in blocking task
            tokio::task::spawn_blocking(move || {
                info!("TUN adapter read loop started for {}", name);
                let mut buffer = vec![0u8; mtu as usize + 4]; // Extra space for protocol header
                
                loop {
                    let result = {
                        let mut dev = match device_clone.lock() {
                            Ok(d) => d,
                            Err(e) => {
                                error!("Failed to lock TUN device: {}", e);
                                break;
                            }
                        };
                        
                        use std::io::Read;
                        dev.read(&mut buffer)
                    };
                    
                    match result {
                        Ok(n) => {
                            if n == 0 {
                                warn!("TUN device {} returned 0 bytes", name);
                                continue;
                            }
                            
                            debug!("TUN read: {} bytes from {}", n, name);
                            let packet = buffer[..n].to_vec();
                            
                            let event_tx_clone = event_tx.clone();
                            let _ = tokio::runtime::Handle::current().block_on(async {
                                event_tx_clone.send(TunEvent::PacketRead(packet)).await
                            });
                        }
                        Err(e) => {
                            error!("TUN read error on {}: {}", name, e);
                            let event_tx_clone = event_tx.clone();
                            let _ = tokio::runtime::Handle::current().block_on(async {
                                event_tx_clone.send(TunEvent::Error(e.to_string())).await
                            });
                            std::thread::sleep(std::time::Duration::from_secs(1));
                        }
                    }
                }
                
                info!("TUN adapter read loop stopped for {}", name);
            });
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            info!("TUN adapter running in simulation mode (no actual device)");
        }
        
        info!("TUN adapter started: {}", self.name);
        Ok(())
    }
    
    /// Send packet to TUN interface
    pub async fn send(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }
        
        // Check packet size
        if packet.len() > self.mtu as usize {
            warn!("Packet size {} exceeds MTU {}", packet.len(), self.mtu);
            return Err(anyhow::anyhow!("Packet too large"));
        }
        
        #[cfg(target_os = "linux")]
        if let Some(device) = &self.device {
            let device_clone = Arc::clone(device);
            let packet_len = packet.len();
            let packet = packet.to_vec();
            
            tokio::task::spawn_blocking(move || {
                let mut dev = device_clone.lock().unwrap();
                use std::io::Write;
                dev.write_all(&packet)
            }).await??;
            
            debug!("TUN send: {} bytes", packet_len);
            return Ok(());
        }
        
        debug!("TUN send (simulated): {} bytes", packet.len());
        Ok(())
    }
    
    /// Write packet asynchronously
    pub async fn write_packet(&self, packet: Vec<u8>) -> Result<()> {
        self.tx.send(packet).await
            .map_err(|e| anyhow::anyhow!("Failed to queue packet: {}", e))?;
        Ok(())
    }
    
    /// Get interface name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get MTU
    pub fn mtu(&self) -> u32 {
        self.mtu
    }
    
    /// Check if TUN device is available
    pub fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.device.is_some()
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tun_adapter_creation() {
        let (adapter, _rx, _event_rx) = TunAdapter::new("ygg0".to_string(), 65535);
        assert_eq!(adapter.name(), "ygg0");
        assert_eq!(adapter.mtu(), 65535);
    }
    
    #[tokio::test]
    async fn test_tun_adapter_send() {
        let (adapter, _rx, _event_rx) = TunAdapter::new("ygg_test".to_string(), 1500);
        
        // Should succeed with valid packet
        let packet = vec![0x60, 0x00, 0x00, 0x00]; // IPv6 header start
        assert!(adapter.send(&packet).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_tun_adapter_oversized_packet() {
        let (adapter, _rx, _event_rx) = TunAdapter::new("ygg_test".to_string(), 1500);
        
        // Should fail with oversized packet
        let packet = vec![0u8; 2000];
        assert!(adapter.send(&packet).await.is_err());
    }
    
    #[tokio::test(flavor = "multi_thread")]
    async fn test_tun_adapter_start() {
        let (mut adapter, _rx, _event_rx) = TunAdapter::new("ygg_test".to_string(), 1500);
        
        // Should start without error (even if device creation fails)
        // Note: This will spawn a background task that reads from TUN device
        // On systems without root privileges, device creation will fail gracefully
        // but start() should still succeed
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            adapter.start()
        ).await;
        
        assert!(result.is_ok(), "start() should complete within timeout");
        assert!(result.unwrap().is_ok(), "start() should succeed");
        
        // Give a moment for any background tasks to initialize
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    
    #[tokio::test]
    async fn test_tun_write_packet() {
        let (adapter, mut rx, _event_rx) = TunAdapter::new("ygg_test".to_string(), 1500);
        
        let packet = vec![1, 2, 3, 4];
        adapter.write_packet(packet.clone()).await.unwrap();
        
        // Should receive the queued packet
        let received = rx.recv().await.unwrap();
        assert_eq!(received, packet);
    }
}
