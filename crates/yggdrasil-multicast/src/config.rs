//! Multicast configuration.

use regex::Regex;

/// Configuration for a specific multicast interface.
#[derive(Debug, Clone)]
pub struct MulticastInterfaceConfig {
    /// Compiled regular expression to match interface names.
    pub regex: Regex,
    /// Whether to send multicast beacons.
    pub beacon: bool,
    /// Whether to listen for multicast beacons.
    pub listen: bool,
    /// Port for the TLS listener (0 = random).
    pub port: u16,
    /// Priority for this interface.
    pub priority: u8,
    /// Password for multicast peers.
    pub password: String,
}

impl MulticastInterfaceConfig {
    /// Create a new multicast interface configuration.
    pub fn new(regex: &str, beacon: bool, listen: bool) -> Result<Self, regex::Error> {
        Ok(Self {
            regex: Regex::new(regex)?,
            beacon,
            listen,
            port: 0,
            priority: 0,
            password: String::new(),
        })
    }

    /// Create a configuration that matches all interfaces.
    pub fn all() -> Self {
        Self {
            regex: Regex::new(".*").unwrap(),
            beacon: true,
            listen: true,
            port: 0,
            priority: 0,
            password: String::new(),
        }
    }

    /// Set the port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: String) -> Self {
        self.password = password;
        self
    }
}

/// Overall multicast configuration.
#[derive(Debug, Clone)]
pub struct MulticastConfig {
    /// Interface configurations.
    pub interfaces: Vec<MulticastInterfaceConfig>,
    /// Multicast group address.
    pub group_addr: String,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![MulticastInterfaceConfig::all()],
            group_addr: "[ff02::114]:9001".to_string(),
        }
    }
}
