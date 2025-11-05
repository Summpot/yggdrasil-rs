/// Admin API Go Compatibility Layer
///
/// This module provides Go-compatible response structures for the Admin API.
/// The Go implementation uses PascalCase field names, while the Rust
/// implementation uses snake_case. This module bridges that gap.

use serde::{Deserialize, Serialize};

/// Go-compatible GetSelf response with PascalCase field names
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetSelfResponseGo {
    #[serde(rename = "BuildName")]
    pub build_name: String,
    #[serde(rename = "BuildVersion")]
    pub build_version: String,
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "Subnet")]
    pub subnet: String,
    #[serde(rename = "RoutingEntries")]
    pub routing_entries: u64,
}

impl From<crate::admin::GetSelfResponse> for GetSelfResponseGo {
    fn from(rust: crate::admin::GetSelfResponse) -> Self {
        Self {
            build_name: rust.build_name,
            build_version: rust.build_version,
            public_key: rust.public_key,
            address: rust.ip_address,
            subnet: rust.subnet,
            routing_entries: rust.routing_entries,
        }
    }
}

/// Go-compatible Peer entry with PascalCase field names
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerEntryGo {
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "URI")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(rename = "Inbound")]
    pub inbound: bool,
    #[serde(rename = "Up")]
    pub up: bool,
    #[serde(rename = "Port")]
    pub port: u64,
    #[serde(rename = "Priority")]
    pub priority: u64,
    #[serde(rename = "Cost")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<u64>,
    #[serde(rename = "RXBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,
    #[serde(rename = "TXBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,
    #[serde(rename = "Uptime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<f64>,
    // Rust-specific enhanced fields (optional for compatibility)
    #[serde(rename = "Coords")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coords: Option<Vec<u64>>,
    #[serde(rename = "Root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(rename = "Latency")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<u64>,
}

impl From<crate::admin::PeerEntry> for PeerEntryGo {
    fn from(rust: crate::admin::PeerEntry) -> Self {
        Self {
            public_key: rust.public_key,
            address: rust.ip_address,
            uri: rust.uri,
            inbound: rust.inbound,
            up: rust.up,
            port: rust.port,
            priority: rust.priority,
            cost: Some(rust.cost),
            rx_bytes: rust.rx_bytes,
            tx_bytes: rust.tx_bytes,
            uptime: rust.uptime,
            coords: rust.coords,
            root: rust.root,
            latency: rust.latency,
        }
    }
}

/// Go-compatible GetPeers response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPeersResponseGo {
    #[serde(rename = "Peers")]
    pub peers: Vec<PeerEntryGo>,
}

impl From<crate::admin::GetPeersResponse> for GetPeersResponseGo {
    fn from(rust: crate::admin::GetPeersResponse) -> Self {
        Self {
            peers: rust.peers.into_iter().map(Into::into).collect(),
        }
    }
}

/// Go-compatible Path entry with PascalCase field names
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PathEntryGo {
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "Path")]
    pub path: Vec<u64>,
}

impl From<crate::admin::PathEntry> for PathEntryGo {
    fn from(rust: crate::admin::PathEntry) -> Self {
        Self {
            public_key: rust.public_key,
            address: rust.ip_address,
            path: rust.path,
        }
    }
}

/// Go-compatible GetPaths response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPathsResponseGo {
    #[serde(rename = "Paths")]
    pub paths: Vec<PathEntryGo>,
}

impl From<crate::admin::GetPathsResponse> for GetPathsResponseGo {
    fn from(rust: crate::admin::GetPathsResponse) -> Self {
        Self {
            paths: rust.paths.into_iter().map(Into::into).collect(),
        }
    }
}

/// Go-compatible Session entry with PascalCase field names
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionEntryGo {
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "RXBytes")]
    pub rx_bytes: u64,
    #[serde(rename = "TXBytes")]
    pub tx_bytes: u64,
    #[serde(rename = "Uptime")]
    pub uptime: f64,
    // Rust-specific enhanced fields
    #[serde(rename = "Coords")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coords: Option<Vec<u64>>,
    #[serde(rename = "Root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

impl From<crate::admin::SessionEntry> for SessionEntryGo {
    fn from(rust: crate::admin::SessionEntry) -> Self {
        Self {
            public_key: rust.public_key,
            address: rust.ip_address,
            rx_bytes: rust.rx_bytes,
            tx_bytes: rust.tx_bytes,
            uptime: rust.uptime,
            coords: rust.coords,
            root: rust.root,
        }
    }
}

/// Go-compatible GetSessions response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetSessionsResponseGo {
    #[serde(rename = "Sessions")]
    pub sessions: Vec<SessionEntryGo>,
}

impl From<crate::admin::GetSessionsResponse> for GetSessionsResponseGo {
    fn from(rust: crate::admin::GetSessionsResponse) -> Self {
        Self {
            sessions: rust.sessions.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getself_go_compat_serialization() {
        let response = GetSelfResponseGo {
            build_name: "yggdrasil".to_string(),
            build_version: "0.5.0".to_string(),
            public_key: "abc123".to_string(),
            address: "200::1".to_string(),
            subnet: "300::/64".to_string(),
            routing_entries: 42,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("BuildName"));
        assert!(json.contains("BuildVersion"));
        assert!(json.contains("PublicKey"));
        assert!(json.contains("Address"));
        assert!(json.contains("Subnet"));
        assert!(json.contains("RoutingEntries"));
    }

    #[test]
    fn test_peer_go_compat_serialization() {
        let peer = PeerEntryGo {
            public_key: "key123".to_string(),
            address: Some("200::2".to_string()),
            uri: Some("tcp://example.com:9001".to_string()),
            inbound: false,
            up: true,
            port: 1,
            priority: 0,
            cost: Some(100),
            rx_bytes: Some(1024),
            tx_bytes: Some(2048),
            uptime: Some(123.45),
            coords: Some(vec![1, 2, 3]),
            root: Some("root_key".to_string()),
            latency: Some(15000000),
        };

        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains("PublicKey"));
        assert!(json.contains("Address"));
        assert!(json.contains("URI"));
        assert!(json.contains("RXBytes"));
        assert!(json.contains("TXBytes"));
        assert!(json.contains("Coords"));
    }
}
