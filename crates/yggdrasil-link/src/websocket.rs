//! WebSocket link implementation.
//!
//! Supports both plain WebSocket (ws://) and WebSocket Secure (wss://) protocols.
//! This provides firewall-friendly connections and browser compatibility.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use yggdrasil_types::PublicKey;

use crate::link::{Link, LinkConfig, LinkError, LinkInfo};

/// A WebSocket link (ws:// or wss://).
pub struct WebSocketLink {
    info: LinkInfo,
    ws_stream: Mutex<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    connected: AtomicBool,
    #[allow(dead_code)]
    config: LinkConfig,
}

impl WebSocketLink {
    /// Connect to a WebSocket server.
    pub async fn connect(
        uri: &str,
        remote_key: PublicKey,
        config: LinkConfig,
    ) -> Result<Self, LinkError> {
        // Connect to the WebSocket server with ygg-ws subprotocol
        let request = http::Request::builder()
            .uri(uri)
            .header("Sec-WebSocket-Protocol", "ygg-ws")
            .body(())
            .map_err(|e| {
                LinkError::Protocol(format!("failed to build WebSocket request: {}", e))
            })?;

        let (ws_stream, _response) = connect_async(request)
            .await
            .map_err(|e| LinkError::Protocol(format!("WebSocket connection failed: {}", e)))?;

        // Get connection information
        let stream = ws_stream.get_ref();
        let (remote_addr, local_addr) = match stream {
            MaybeTlsStream::Plain(tcp) => (tcp.peer_addr()?, tcp.local_addr()?),
            MaybeTlsStream::NativeTls(tls) => {
                let tcp = tls.get_ref().get_ref().get_ref();
                (tcp.peer_addr()?, tcp.local_addr()?)
            }
            _ => return Err(LinkError::Protocol("unsupported TLS backend".to_string())),
        };

        let link_type = if uri.starts_with("wss://") {
            "wss"
        } else {
            "ws"
        };

        Ok(Self {
            info: LinkInfo {
                remote_key,
                remote_addr,
                local_addr,
                link_type: link_type.to_string(),
                outbound: true,
                established: Instant::now(),
            },
            ws_stream: Mutex::new(ws_stream),
            connected: AtomicBool::new(true),
            config,
        })
    }

    /// Create from an accepted WebSocket connection (for server side).
    pub fn from_accepted(
        ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        remote_key: PublicKey,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        is_secure: bool,
        config: LinkConfig,
    ) -> Self {
        let link_type = if is_secure { "wss" } else { "ws" };

        Self {
            info: LinkInfo {
                remote_key,
                remote_addr,
                local_addr,
                link_type: link_type.to_string(),
                outbound: false,
                established: Instant::now(),
            },
            ws_stream: Mutex::new(ws_stream),
            connected: AtomicBool::new(true),
            config,
        }
    }
}

#[async_trait]
impl Link for WebSocketLink {
    fn info(&self) -> &LinkInfo {
        &self.info
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn recv(&self) -> Result<Vec<u8>, LinkError> {
        let mut ws_stream = self.ws_stream.lock().await;

        loop {
            match ws_stream.next().await {
                Some(Ok(Message::Binary(data))) => {
                    // data is already Bytes, convert to Vec<u8>
                    return Ok(data.into());
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    // Automatically handled by tungstenite, continue reading
                    continue;
                }
                Some(Ok(Message::Close(_))) => {
                    self.connected.store(false, Ordering::Relaxed);
                    return Err(LinkError::Closed);
                }
                Some(Ok(msg)) => {
                    // Ignore text and other message types, yggdrasil only uses binary
                    tracing::trace!("Ignoring non-binary WebSocket message: {:?}", msg);
                    continue;
                }
                Some(Err(e)) => {
                    self.connected.store(false, Ordering::Relaxed);
                    return Err(LinkError::Protocol(format!("WebSocket error: {}", e)));
                }
                None => {
                    self.connected.store(false, Ordering::Relaxed);
                    return Err(LinkError::Closed);
                }
            }
        }
    }

    async fn send(&self, data: &[u8]) -> Result<(), LinkError> {
        let mut ws_stream = self.ws_stream.lock().await;
        // Convert slice to Bytes for WebSocket Message
        let bytes = bytes::Bytes::copy_from_slice(data);
        ws_stream.send(Message::Binary(bytes)).await.map_err(|e| {
            self.connected.store(false, Ordering::Relaxed);
            LinkError::Protocol(format!("WebSocket write failed: {}", e))
        })?;

        Ok(())
    }

    async fn close(&self) -> Result<(), LinkError> {
        self.connected.store(false, Ordering::Relaxed);
        let mut ws_stream = self.ws_stream.lock().await;
        ws_stream
            .close(None)
            .await
            .map_err(|e| LinkError::Protocol(format!("WebSocket close failed: {}", e)))?;
        Ok(())
    }
}
