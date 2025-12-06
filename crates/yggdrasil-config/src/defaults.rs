//! Platform-specific default values.

use crate::MulticastInterfaceConfig;

/// Platform-specific defaults.
#[derive(Debug, Clone)]
pub struct Defaults {
    /// Default admin listen address.
    pub default_admin_listen: String,
    /// Default multicast interfaces.
    pub default_multicast_interfaces: Vec<MulticastInterfaceConfig>,
    /// Default TUN interface name.
    pub default_if_name: String,
    /// Default MTU.
    pub default_if_mtu: u64,
}

/// Get platform-specific defaults.
pub fn get_defaults() -> Defaults {
    #[cfg(target_os = "windows")]
    {
        Defaults {
            default_admin_listen: "tcp://localhost:9001".to_string(),
            default_multicast_interfaces: vec![MulticastInterfaceConfig {
                regex: ".*".to_string(),
                beacon: true,
                listen: true,
                ..Default::default()
            }],
            default_if_name: "Yggdrasil".to_string(),
            default_if_mtu: 65535,
        }
    }

    #[cfg(target_os = "macos")]
    {
        Defaults {
            default_admin_listen: "unix:///var/run/yggdrasil/yggdrasil.sock".to_string(),
            default_multicast_interfaces: vec![MulticastInterfaceConfig {
                regex: "en.*".to_string(),
                beacon: true,
                listen: true,
                ..Default::default()
            }],
            default_if_name: "auto".to_string(),
            default_if_mtu: 65535,
        }
    }

    #[cfg(target_os = "linux")]
    {
        Defaults {
            default_admin_listen: "unix:///var/run/yggdrasil.sock".to_string(),
            default_multicast_interfaces: vec![MulticastInterfaceConfig {
                regex: ".*".to_string(),
                beacon: true,
                listen: true,
                ..Default::default()
            }],
            default_if_name: "auto".to_string(),
            default_if_mtu: 65535,
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Defaults {
            default_admin_listen: "tcp://localhost:9001".to_string(),
            default_multicast_interfaces: vec![MulticastInterfaceConfig {
                regex: ".*".to_string(),
                beacon: true,
                listen: true,
                ..Default::default()
            }],
            default_if_name: "auto".to_string(),
            default_if_mtu: 65535,
        }
    }
}
