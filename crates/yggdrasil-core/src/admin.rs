use anyhow::{Context, Result};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
#[cfg(unix)]
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(not(unix))]
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

pub struct AdminClient {
    endpoint: String,
}

pub struct AdminServer {
    endpoint: String,
    handlers: Arc<HashMap<String, HandlerInfo>>,
}

struct HandlerInfo {
    description: String,
    fields: Vec<String>,
}

pub type HandlerFunc = Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value> + Send + Sync>;

pub type AsyncHandlerFunc = Arc<
    dyn Fn(
            &str,
            serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send>>
        + Send
        + Sync,
>;

impl AdminClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    async fn send_request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        request_name: &str,
        arguments: &T,
    ) -> Result<R> {
        #[cfg(unix)]
        {
            // Parse endpoint to check if it's a unix socket
            let socket_path = if self.endpoint.starts_with("unix://") {
                self.endpoint.strip_prefix("unix://").unwrap()
            } else {
                self.endpoint.as_str()
            };

            // Connect to unix socket
            let stream = UnixStream::connect(socket_path).await.context(format!(
                "Failed to connect to admin socket: {}",
                socket_path
            ))?;

            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);

            Self::process_request(request_name, arguments, &mut reader, &mut writer).await
        }

        #[cfg(not(unix))]
        {
            // Parse endpoint as TCP address
            let addr = if self.endpoint.starts_with("tcp://") {
                self.endpoint.strip_prefix("tcp://").unwrap()
            } else {
                self.endpoint.as_str()
            };

            // Connect to TCP socket
            let stream = TcpStream::connect(addr)
                .await
                .context(format!("Failed to connect to admin socket: {}", addr))?;

            let (reader, writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut writer = writer;

            Self::process_request(request_name, arguments, &mut reader, &mut writer).await
        }
    }

    async fn process_request<T: Serialize, R: for<'de> Deserialize<'de>, RD, WR>(
        request_name: &str,
        arguments: &T,
        reader: &mut BufReader<RD>,
        writer: &mut WR,
    ) -> Result<R>
    where
        RD: tokio::io::AsyncRead + Unpin,
        WR: tokio::io::AsyncWrite + Unpin,
    {
        // Prepare request
        let request = AdminSocketRequest {
            request: request_name.to_string(),
            arguments: Some(serde_json::to_value(arguments)?),
            keepalive: false,
        };

        // Send request
        let request_json = serde_json::to_string(&request)?;
        writer.write_all(request_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        // Read response (may be multi-line JSON)
        let mut response_text = String::new();
        let mut brace_count = 0;
        let mut in_response = false;

        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line).await?;

            if bytes_read == 0 {
                break;
            }

            response_text.push_str(&line);

            for ch in line.chars() {
                match ch {
                    '{' => {
                        brace_count += 1;
                        in_response = true;
                    }
                    '}' => {
                        brace_count -= 1;
                        if in_response && brace_count == 0 {
                            let response: AdminSocketResponse<R> =
                                serde_json::from_str(&response_text).context(format!(
                                    "Failed to parse admin response: {}",
                                    response_text.trim()
                                ))?;

                            if response.status == "success" {
                                return response.response.ok_or_else(|| {
                                    anyhow::anyhow!("Success response missing response field")
                                });
                            } else {
                                return Err(anyhow::anyhow!(
                                    "Admin API error: {}",
                                    response
                                        .error
                                        .unwrap_or_else(|| "Unknown error".to_string())
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Err(anyhow::anyhow!("Incomplete response from admin socket"))
    }

    pub async fn get_self(&self) -> Result<GetSelfResponse> {
        self.send_request("getSelf", &GetSelfRequest {}).await
    }

    pub async fn get_peers(&self) -> Result<GetPeersResponse> {
        self.send_request("getPeers", &GetPeersRequest {}).await
    }

    pub async fn get_paths(&self) -> Result<GetPathsResponse> {
        self.send_request("getPaths", &GetPathsRequest {}).await
    }

    pub async fn get_sessions(&self) -> Result<GetSessionsResponse> {
        self.send_request("getSessions", &GetSessionsRequest {})
            .await
    }

    pub async fn add_peer(&self, uri: &str, interface: Option<&str>) -> Result<AddPeerResponse> {
        let request = AddPeerRequest {
            uri: uri.to_string(),
            interface: interface.map(|s| s.to_string()),
        };
        self.send_request("addPeer", &request).await
    }

    pub async fn remove_peer(
        &self,
        uri: &str,
        interface: Option<&str>,
    ) -> Result<RemovePeerResponse> {
        let request = RemovePeerRequest {
            uri: uri.to_string(),
            interface: interface.map(|s| s.to_string()),
        };
        self.send_request("removePeer", &request).await
    }

    pub async fn list(&self) -> Result<ListResponse> {
        self.send_request("list", &ListRequest {}).await
    }
}

impl AdminServer {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let mut handlers = HashMap::new();

        // Register default handlers
        handlers.insert(
            "list".to_string(),
            HandlerInfo {
                description: "List available commands".to_string(),
                fields: vec![],
            },
        );

        handlers.insert(
            "getSelf".to_string(),
            HandlerInfo {
                description: "Show details about this node".to_string(),
                fields: vec![],
            },
        );

        handlers.insert(
            "getPeers".to_string(),
            HandlerInfo {
                description: "Show directly connected peers".to_string(),
                fields: vec![],
            },
        );

        handlers.insert(
            "getPaths".to_string(),
            HandlerInfo {
                description: "Show established paths through this node".to_string(),
                fields: vec![],
            },
        );

        handlers.insert(
            "getSessions".to_string(),
            HandlerInfo {
                description: "Show established traffic sessions with remote nodes".to_string(),
                fields: vec![],
            },
        );

        handlers.insert(
            "addPeer".to_string(),
            HandlerInfo {
                description: "Add a peer to the peer list".to_string(),
                fields: vec!["uri".to_string(), "interface".to_string()],
            },
        );

        handlers.insert(
            "removePeer".to_string(),
            HandlerInfo {
                description: "Remove a peer from the peer list".to_string(),
                fields: vec!["uri".to_string(), "interface".to_string()],
            },
        );

        Self {
            endpoint: endpoint.into(),
            handlers: Arc::new(handlers),
        }
    }

    pub async fn start<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: Fn(&str, serde_json::Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<serde_json::Value>> + Send + 'static,
    {
        #[cfg(unix)]
        {
            let socket_path = if self.endpoint.starts_with("unix://") {
                self.endpoint.strip_prefix("unix://").unwrap()
            } else {
                self.endpoint.as_str()
            };

            // Remove existing socket file if it exists
            if Path::new(socket_path).exists() {
                info!("Removing existing admin socket: {}", socket_path);
                tokio::fs::remove_file(socket_path).await?;
            }

            // Create listener
            let listener = UnixListener::bind(socket_path)
                .context(format!("Failed to bind admin socket: {}", socket_path))?;

            // Set socket permissions
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o660);
            std::fs::set_permissions(socket_path, permissions)?;

            info!("Admin socket listening on {}", socket_path);

            let handlers = Arc::clone(&self.handlers);
            let handler = Arc::new(handler);

            // Accept connections
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let handlers = Arc::clone(&handlers);
                        let handler = Arc::clone(&handler);

                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_connection_unix(stream, handlers, handler).await
                            {
                                error!("Error handling admin connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting admin connection: {}", e);
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            let addr = if self.endpoint.starts_with("tcp://") {
                self.endpoint.strip_prefix("tcp://").unwrap()
            } else {
                self.endpoint.as_str()
            };

            // Create TCP listener
            let listener = TcpListener::bind(addr)
                .await
                .context(format!("Failed to bind admin socket: {}", addr))?;

            info!("Admin socket listening on {}", addr);

            let handlers = Arc::clone(&self.handlers);
            let handler = Arc::new(handler);

            // Accept connections
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let handlers = Arc::clone(&handlers);
                        let handler = Arc::clone(&handler);

                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_connection_tcp(stream, handlers, handler).await
                            {
                                error!("Error handling admin connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting admin connection: {}", e);
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    async fn handle_connection_unix<F, Fut>(
        stream: UnixStream,
        handlers: Arc<HashMap<String, HandlerInfo>>,
        handler: Arc<F>,
    ) -> Result<()>
    where
        F: Fn(&str, serde_json::Value) -> Fut + Send + Sync,
        Fut: Future<Output = Result<serde_json::Value>> + Send,
    {
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = writer;

        Self::handle_connection_impl(&mut reader, &mut writer, handlers, handler).await
    }

    #[cfg(not(unix))]
    async fn handle_connection_tcp<F, Fut>(
        stream: TcpStream,
        handlers: Arc<HashMap<String, HandlerInfo>>,
        handler: Arc<F>,
    ) -> Result<()>
    where
        F: Fn(&str, serde_json::Value) -> Fut + Send + Sync,
        Fut: Future<Output = Result<serde_json::Value>> + Send,
    {
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = writer;

        Self::handle_connection_impl(&mut reader, &mut writer, handlers, handler).await
    }

    async fn handle_connection_impl<F, Fut, RD, WR>(
        reader: &mut BufReader<RD>,
        writer: &mut WR,
        handlers: Arc<HashMap<String, HandlerInfo>>,
        handler: Arc<F>,
    ) -> Result<()>
    where
        F: Fn(&str, serde_json::Value) -> Fut + Send + Sync,
        Fut: Future<Output = Result<serde_json::Value>> + Send,
        RD: tokio::io::AsyncRead + Unpin,
        WR: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let mut _response_text = String::new();
            let mut brace_count = 0;
            let mut in_request = false;
            let mut request_json = String::new();

            // Read request (may be multi-line JSON)
            loop {
                let mut line = String::new();
                let bytes_read = reader.read_line(&mut line).await?;

                if bytes_read == 0 {
                    // Connection closed
                    return Ok(());
                }

                request_json.push_str(&line);

                for ch in line.chars() {
                    match ch {
                        '{' => {
                            brace_count += 1;
                            in_request = true;
                        }
                        '}' => {
                            brace_count -= 1;
                            if in_request && brace_count == 0 {
                                // Complete request received
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if in_request && brace_count == 0 {
                    break;
                }
            }

            // Parse request
            let request: AdminSocketRequest = match serde_json::from_str(&request_json) {
                Ok(req) => req,
                Err(e) => {
                    let error_response = AdminSocketResponseOut::<serde_json::Value> {
                        status: "error".to_string(),
                        error: Some(format!("Failed to parse request: {}", e)),
                        response: None,
                    };
                    let json = serde_json::to_string_pretty(&error_response)?;
                    writer.write_all(json.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                    continue;
                }
            };

            debug!("Admin request: {}", request.request);

            // Handle special "list" command
            if request.request == "list" {
                let mut list = Vec::new();
                for (command, info) in handlers.iter() {
                    list.push(ListEntry {
                        command: command.clone(),
                        description: info.description.clone(),
                        fields: info.fields.clone(),
                    });
                }
                list.sort_by(|a, b| a.command.cmp(&b.command));

                let response = AdminSocketResponseOut {
                    status: "success".to_string(),
                    error: None,
                    response: Some(ListResponse { list }),
                };

                let json = serde_json::to_string_pretty(&response)?;
                writer.write_all(json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            } else {
                // Call handler
                let arguments = request.arguments.unwrap_or(serde_json::json!({}));
                let response = match handler(&request.request, arguments).await {
                    Ok(result) => AdminSocketResponseOut {
                        status: "success".to_string(),
                        error: None,
                        response: Some(result),
                    },
                    Err(e) => AdminSocketResponseOut::<serde_json::Value> {
                        status: "error".to_string(),
                        error: Some(e.to_string()),
                        response: None,
                    },
                };

                let json = serde_json::to_string_pretty(&response)?;
                writer.write_all(json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }

            // Check if we should keep the connection alive
            if !request.keepalive {
                break;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminSocketRequest {
    request: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<serde_json::Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_false")]
    keepalive: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Debug, Deserialize)]
struct AdminSocketResponse<T> {
    status: String,
    #[serde(default)]
    error: Option<String>,
    response: Option<T>,
}

#[derive(Debug, Serialize)]
struct AdminSocketResponseOut<T: Serialize> {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSelfRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSelfResponse {
    pub build_name: String,
    pub build_version: String,
    #[serde(rename = "key")]
    pub public_key: String,
    #[serde(rename = "address")]
    pub ip_address: String,
    pub routing_entries: u64,
    pub subnet: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetPeersRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetPeersResponse {
    pub peers: Vec<PeerEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerEntry {
    #[serde(rename = "remote")]
    pub uri: Option<String>,
    pub up: bool,
    pub inbound: bool,
    #[serde(rename = "address")]
    pub ip_address: Option<String>,
    #[serde(rename = "key")]
    pub public_key: String,
    pub port: u64,
    pub priority: u64,
    pub cost: u64,
    #[serde(rename = "bytes_recvd")]
    pub rx_bytes: Option<u64>,
    #[serde(rename = "bytes_sent")]
    pub tx_bytes: Option<u64>,
    #[serde(rename = "rate_recvd")]
    pub rx_rate: Option<u64>,
    #[serde(rename = "rate_sent")]
    pub tx_rate: Option<u64>,
    pub uptime: Option<f64>,
    pub latency: Option<u64>,
    pub last_error_time: Option<u64>,
    pub last_error: Option<String>,
    /// Tree-space coordinates (path through spanning tree)
    #[serde(rename = "coords")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coords: Option<Vec<u64>>,
    /// Root node public key (in spanning tree)
    #[serde(rename = "root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetPathsRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetPathsResponse {
    pub paths: Vec<PathEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PathEntry {
    #[serde(rename = "key")]
    pub public_key: String,
    #[serde(rename = "address")]
    pub ip_address: String,
    pub path: Vec<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSessionsRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSessionsResponse {
    pub sessions: Vec<SessionEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionEntry {
    #[serde(rename = "key")]
    pub public_key: String,
    #[serde(rename = "address")]
    pub ip_address: String,
    #[serde(rename = "coords")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coords: Option<Vec<u64>>,
    #[serde(rename = "root")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(rename = "bytes_recvd")]
    pub rx_bytes: u64,
    #[serde(rename = "bytes_sent")]
    pub tx_bytes: u64,
    #[serde(rename = "rate_recvd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_rate: Option<u64>,
    #[serde(rename = "rate_sent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate: Option<u64>,
    #[serde(rename = "latency_us")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<u64>,
    pub uptime: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddPeerRequest {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddPeerResponse {
    pub success: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovePeerRequest {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovePeerResponse {
    pub success: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub list: Vec<ListEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListEntry {
    pub command: String,
    pub description: String,
    #[serde(default)]
    pub fields: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = AdminSocketRequest {
            request: "getSelf".to_string(),
            arguments: Some(serde_json::json!({})),
            keepalive: false,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("getSelf"));
    }

    #[test]
    fn test_response_types_deserialization() {
        let json = r#"{"build_name":"yggdrasil","build_version":"0.5.0","key":"abc","address":"200::1","routing_entries":42,"subnet":"300::/64"}"#;
        let _: GetSelfResponse = serde_json::from_str(json).unwrap();

        let json = r#"{"peers":[]}"#;
        let _: GetPeersResponse = serde_json::from_str(json).unwrap();

        let json = r#"{"paths":[]}"#;
        let _: GetPathsResponse = serde_json::from_str(json).unwrap();

        let json = r#"{"sessions":[]}"#;
        let _: GetSessionsResponse = serde_json::from_str(json).unwrap();
    }
}
