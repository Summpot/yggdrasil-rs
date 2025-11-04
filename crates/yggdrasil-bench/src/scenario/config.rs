#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

/// Protocol transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Tls,
    Quic,
    Ws,  // WebSocket
    Wss, // WebSocket Secure
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Tls => write!(f, "tls"),
            Protocol::Quic => write!(f, "quic"),
            Protocol::Ws => write!(f, "ws"),
            Protocol::Wss => write!(f, "wss"),
        }
    }
}

/// Overlay network configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Overlay {
    Ipv4,
    Ipv6,
    Udp,
    Tcp,
    Quic,
}

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Overlay::Ipv4 => write!(f, "ipv4"),
            Overlay::Ipv6 => write!(f, "ipv6"),
            Overlay::Udp => write!(f, "udp"),
            Overlay::Tcp => write!(f, "tcp"),
            Overlay::Quic => write!(f, "quic"),
        }
    }
}

/// Single benchmark scenario configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub proto: Protocol,
    pub overlay: Overlay,
    pub packet_size: usize,
    pub warmup_count: u64,
    pub sample_duration_secs: u64,
    pub concurrency: usize,
    #[serde(default = "default_repeat")]
    pub repeat: usize,
}

fn default_repeat() -> usize {
    5
}

impl Scenario {
    pub fn id(&self) -> String {
        format!("{}_{}", self.proto, self.overlay)
    }
}

/// Collection of benchmark scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioConfig {
    pub scenarios: Vec<Scenario>,
}

impl ScenarioConfig {
    /// Load scenarios from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read scenario file: {:?}", path.as_ref()))?;

        let config: ScenarioConfig =
            toml::from_str(&content).context("Failed to parse scenario TOML")?;

        Ok(config)
    }

    /// Generate default scenario matrix (proto × overlay cartesian product)
    pub fn default_matrix() -> Self {
        let protocols = vec![
            Protocol::Tcp,
            Protocol::Tls,
            Protocol::Quic,
            Protocol::Ws,
            Protocol::Wss,
        ];

        let overlays = vec![
            Overlay::Ipv4,
            Overlay::Ipv6,
            Overlay::Udp,
            Overlay::Tcp,
            Overlay::Quic,
        ];

        let mut scenarios = Vec::new();

        for proto in &protocols {
            for overlay in &overlays {
                scenarios.push(Scenario {
                    name: format!("{} over {}", proto, overlay),
                    proto: *proto,
                    overlay: *overlay,
                    packet_size: 1024,
                    warmup_count: 1000,
                    sample_duration_secs: 30,
                    concurrency: 1,
                    repeat: 5,
                });
            }
        }

        Self { scenarios }
    }

    /// Generate lightweight scenario matrix for PR testing
    pub fn lightweight_matrix() -> Self {
        let mut config = Self::default_matrix();

        // Reduce duration and samples for faster PR testing
        for scenario in &mut config.scenarios {
            scenario.sample_duration_secs = 10;
            scenario.warmup_count = 100;
            scenario.repeat = 2;
        }

        // Keep only subset of combinations
        config.scenarios.retain(|s| {
            matches!(s.proto, Protocol::Tcp | Protocol::Quic)
                && matches!(s.overlay, Overlay::Ipv6 | Overlay::Tcp)
        });

        config
    }

    pub fn scenario_count(&self) -> usize {
        self.scenarios.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_id() {
        let scenario = Scenario {
            name: "Test".to_string(),
            proto: Protocol::Tcp,
            overlay: Overlay::Ipv6,
            packet_size: 1024,
            warmup_count: 100,
            sample_duration_secs: 10,
            concurrency: 1,
            repeat: 5,
        };

        assert_eq!(scenario.id(), "tcp_ipv6");
    }

    #[test]
    fn test_default_matrix() {
        let config = ScenarioConfig::default_matrix();
        assert_eq!(config.scenario_count(), 5 * 5); // 5 protocols × 5 overlays
    }

    #[test]
    fn test_lightweight_matrix() {
        let config = ScenarioConfig::lightweight_matrix();
        assert!(config.scenario_count() < ScenarioConfig::default_matrix().scenario_count());

        for scenario in &config.scenarios {
            assert!(scenario.sample_duration_secs <= 10);
            assert!(scenario.warmup_count <= 100);
            assert!(scenario.repeat <= 2);
        }
    }

    #[test]
    fn test_toml_serialization() {
        let config = ScenarioConfig::default_matrix();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: ScenarioConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.scenario_count(), config.scenario_count());
    }
}
