//! TUN adapter implementation.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr};

use net_route::{Handle as RouteHandle, Route};
use thiserror::Error;
use tokio::sync::RwLock;
use tun_rs::{AsyncDevice, DeviceBuilder};
use yggdrasil_address::{Address, Subnet};

/// TUN adapter errors.
#[derive(Debug, Error)]
pub enum TunError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TUN device error: {0}")]
    Device(String),
    #[error("not started")]
    NotStarted,
    #[error("already started")]
    AlreadyStarted,
}

/// TUN adapter configuration.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name (or "auto" for automatic).
    pub name: String,
    /// MTU size.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "auto".to_string(),
            mtu: 65535,
        }
    }
}

/// TUN adapter for the Yggdrasil network.
pub struct TunAdapter {
    config: TunConfig,
    address: Address,
    subnet: Subnet,
    device: RwLock<Option<AsyncDevice>>,
    route: RwLock<Option<Route>>,
}

impl TunAdapter {
    /// Create a new TUN adapter.
    pub fn new(address: Address, subnet: Subnet, config: TunConfig) -> Self {
        Self {
            config,
            address,
            subnet,
            device: RwLock::new(None),
            route: RwLock::new(None),
        }
    }

    /// Start the TUN adapter.
    pub async fn start(&self) -> Result<(), TunError> {
        if self.device.read().await.is_some() {
            return Err(TunError::AlreadyStarted);
        }

        // Ensure wintun.dll is available on Windows
        #[cfg(windows)]
        {
            crate::wintun_dll::ensure_wintun_dll()?;
        }

        // Convert our Address to Ipv6Addr
        let addr_bytes = self.address.as_bytes();
        let ipv6_addr = Ipv6Addr::from(*addr_bytes);

        // Build the TUN device
        let mut builder = DeviceBuilder::new();

        // Set interface name if not "auto"
        if self.config.name != "auto" {
            builder = builder.name(&self.config.name);
        } else {
            // Use a default name based on platform
            #[cfg(windows)]
            {
                builder = builder.name("Yggdrasil");
            }
            #[cfg(not(windows))]
            {
                builder = builder.name("ygg0");
            }
        }

        // Configure IPv6 address - /128 for the node address
        builder = builder.ipv6(ipv6_addr, 128u8);

        // Add the subnet address with /64 prefix
        // The subnet is the first 8 bytes, we need to construct the full address
        let subnet_bytes = self.subnet.as_bytes();
        let mut full_subnet = [0u8; 16];
        full_subnet[..8].copy_from_slice(subnet_bytes);
        let subnet_ipv6 = Ipv6Addr::from(full_subnet);

        // Add route for the subnet
        builder = builder.ipv6(subnet_ipv6, 64u8);

        // Set MTU
        builder = builder.mtu(self.config.mtu);

        // Platform-specific configurations
        #[cfg(windows)]
        {
            builder = builder.with(|opt| {
                opt.ring_capacity(8 * 1024 * 1024); // 8MB ring buffer
            });
        }

        let device = builder
            .build_async()
            .map_err(|e| TunError::Device(e.to_string()))?;

        let if_name = device.name().map_err(TunError::Io)?;
        let if_index = device.if_index().map_err(TunError::Io)?;

        // Install global Yggdrasil route 200::/7 via the TUN interface
        let mut route = Route::new(IpAddr::V6(Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0)), 7u8)
            .with_ifindex(if_index);

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            // Match the kernel's default metric for on-link routes
            route = route.with_metric(256);
        }

        let route_handle = RouteHandle::new().map_err(|e| {
            TunError::Device(format!(
                "failed to initialize routing handle for TUN route: {}",
                e
            ))
        })?;

        let mut installed_route: Option<Route> = None;

        match route_handle.add(&route).await {
            Ok(()) => {
                installed_route = Some(route.clone());
                tracing::info!(
                    dest = "200::/7",
                    if_index,
                    metric = 256u32,
                    "Added global Yggdrasil route via TUN"
                );
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                tracing::debug!(
                    dest = "200::/7",
                    if_index,
                    "Global Yggdrasil route already exists"
                );
            }
            Err(e) => {
                return Err(TunError::Device(format!(
                    "failed to add global Yggdrasil route: {}",
                    e
                )));
            }
        }

        {
            let mut route_guard = self.route.write().await;
            *route_guard = installed_route;
        }

        {
            let mut device_guard = self.device.write().await;
            *device_guard = Some(device);
        }

        tracing::info!(name = %if_name, address = %ipv6_addr, mtu = self.config.mtu, "TUN adapter started");

        Ok(())
    }

    /// Stop the TUN adapter.
    pub async fn stop(&self) -> Result<(), TunError> {
        if self.device.read().await.is_none() {
            return Err(TunError::NotStarted);
        }

        // Remove the global route if we installed it
        if let Some(route) = { self.route.write().await.take() } {
            match RouteHandle::new() {
                Ok(handle) => {
                    if let Err(e) = handle.delete(&route).await {
                        tracing::warn!(
                            error = %e,
                            dest = "200::/7",
                            "Failed to remove global Yggdrasil route"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        dest = "200::/7",
                        "Failed to initialize routing handle to remove global route"
                    );
                }
            }
        }

        // Drop the device to close it
        let mut device_guard = self.device.write().await;
        *device_guard = None;

        tracing::info!("TUN adapter stopped");
        Ok(())
    }

    /// Send a packet through the TUN interface.
    pub async fn send(&self, data: &[u8]) -> Result<(), TunError> {
        let device_guard = self.device.read().await;
        let device = device_guard.as_ref().ok_or(TunError::NotStarted)?;
        device.send(data).await?;
        Ok(())
    }

    /// Receive a packet from the TUN interface.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let device_guard = self.device.read().await;
        let device = device_guard.as_ref().ok_or(TunError::NotStarted)?;
        let len = device.recv(buf).await?;
        Ok(len)
    }

    /// Check if the adapter is running.
    pub async fn is_running(&self) -> bool {
        self.device.read().await.is_some()
    }

    /// Get the TUN adapter configuration.
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Get the IPv6 address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the subnet.
    pub fn subnet(&self) -> &Subnet {
        &self.subnet
    }
}
