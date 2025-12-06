//! Admin socket client for communicating with a running Yggdrasil node.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Admin client errors.
#[derive(Debug, Error)]
pub enum AdminError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("admin socket error: {0}")]
    AdminSocket(String),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
}

/// Admin socket request.
#[derive(Debug, Serialize)]
pub struct AdminRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
}

/// Admin socket response.
#[derive(Debug, Deserialize)]
pub struct AdminResponse {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub response: Option<serde_json::Value>,
}

/// Admin client for communicating with a running Yggdrasil node.
pub struct AdminClient {
    endpoint: String,
}

impl AdminClient {
    /// Create a new admin client.
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
        }
    }

    /// Send a request and receive a response.
    pub fn request(
        &self,
        name: &str,
        args: Option<serde_json::Value>,
    ) -> Result<AdminResponse, AdminError> {
        let request = AdminRequest {
            name: name.to_string(),
            arguments: args,
        };

        let request_json = serde_json::to_string(&request)?;
        let response_json = self.send_raw(&request_json)?;
        let response: AdminResponse = serde_json::from_str(&response_json)?;

        if response.status == "error" {
            return Err(AdminError::AdminSocket(
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string()),
            ));
        }

        Ok(response)
    }

    /// Send a raw JSON request and receive a raw JSON response.
    fn send_raw(&self, request: &str) -> Result<String, AdminError> {
        if self.endpoint.starts_with("tcp://") {
            self.send_tcp(request)
        } else if self.endpoint.starts_with("unix://") {
            #[cfg(unix)]
            {
                self.send_unix(request)
            }
            #[cfg(not(unix))]
            {
                Err(AdminError::InvalidEndpoint(
                    "Unix sockets are not supported on this platform".to_string(),
                ))
            }
        } else {
            // Assume TCP if no scheme
            self.send_tcp(request)
        }
    }

    /// Send request over TCP.
    fn send_tcp(&self, request: &str) -> Result<String, AdminError> {
        let addr = self
            .endpoint
            .strip_prefix("tcp://")
            .unwrap_or(&self.endpoint);

        let mut stream = TcpStream::connect(addr)
            .map_err(|e| AdminError::Connection(format!("failed to connect to {}: {}", addr, e)))?;

        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        writeln!(stream, "{}", request)?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;

        Ok(response)
    }

    /// Send request over Unix socket.
    #[cfg(unix)]
    fn send_unix(&self, request: &str) -> Result<String, AdminError> {
        let path = self
            .endpoint
            .strip_prefix("unix://")
            .unwrap_or(&self.endpoint);

        let mut stream = UnixStream::connect(path)
            .map_err(|e| AdminError::Connection(format!("failed to connect to {}: {}", path, e)))?;

        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        writeln!(stream, "{}", request)?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;

        Ok(response)
    }
}

/// Response types for various admin commands.
pub mod responses {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ListEntry {
        pub command: String,
        pub description: String,
        #[serde(default)]
        pub fields: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct ListResponse {
        pub list: Vec<ListEntry>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GetSelfResponse {
        pub build_name: String,
        pub build_version: String,
        #[serde(rename = "ipAddress")]
        pub ip_address: String,
        pub subnet: String,
        pub routing_entries: u64,
        pub public_key: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PeerEntry {
        #[serde(rename = "URI")]
        pub uri: String,
        pub up: bool,
        pub inbound: bool,
        #[serde(rename = "ipAddress")]
        pub ip_address: String,
        #[serde(default)]
        pub uptime: f64,
        #[serde(default)]
        pub latency: u64,
        #[serde(rename = "RXBytes", default)]
        pub rx_bytes: u64,
        #[serde(rename = "TXBytes", default)]
        pub tx_bytes: u64,
        #[serde(rename = "RXRate", default)]
        pub rx_rate: u64,
        #[serde(rename = "TXRate", default)]
        pub tx_rate: u64,
        #[serde(default)]
        pub priority: u64,
        #[serde(default)]
        pub cost: u64,
        #[serde(default)]
        pub last_error: String,
        #[serde(default)]
        pub last_error_time: f64,
    }

    #[derive(Debug, Deserialize)]
    pub struct GetPeersResponse {
        pub peers: Vec<PeerEntry>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TreeEntry {
        pub public_key: String,
        #[serde(rename = "ipAddress")]
        pub ip_address: String,
        pub parent: String,
        pub sequence: u64,
    }

    #[derive(Debug, Deserialize)]
    pub struct GetTreeResponse {
        pub tree: Vec<TreeEntry>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PathEntry {
        pub public_key: String,
        #[serde(rename = "ipAddress")]
        pub ip_address: String,
        pub path: Vec<u64>,
        pub sequence: u64,
    }

    #[derive(Debug, Deserialize)]
    pub struct GetPathsResponse {
        pub paths: Vec<PathEntry>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SessionEntry {
        pub public_key: String,
        #[serde(rename = "ipAddress")]
        pub ip_address: String,
        pub uptime: f64,
        #[serde(rename = "RXBytes", default)]
        pub rx_bytes: u64,
        #[serde(rename = "TXBytes", default)]
        pub tx_bytes: u64,
    }

    #[derive(Debug, Deserialize)]
    pub struct GetSessionsResponse {
        pub sessions: Vec<SessionEntry>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MulticastInterface {
        pub name: String,
        pub address: String,
        pub beacon: bool,
        pub listen: bool,
        pub password: bool,
    }

    #[derive(Debug, Deserialize)]
    pub struct GetMulticastInterfacesResponse {
        pub interfaces: Vec<MulticastInterface>,
    }

    #[derive(Debug, Deserialize)]
    pub struct GetTUNResponse {
        pub enabled: bool,
        #[serde(default)]
        pub name: String,
        #[serde(rename = "MTU", default)]
        pub mtu: u64,
    }
}
