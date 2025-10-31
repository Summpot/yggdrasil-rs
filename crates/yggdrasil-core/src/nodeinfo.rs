use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::timeout;

use crate::proto::{TYPE_PROTO_NODEINFO_REQUEST, TYPE_PROTO_NODEINFO_RESPONSE, TYPE_SESSION_PROTO};

const MAX_NODEINFO_SIZE: usize = 16384; // 16KB max
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

type NodeInfoCallback = Box<dyn FnOnce(JsonValue) + Send + 'static>;

struct CallbackInfo {
    // Use Arc<Mutex<Option<>>> to make FnOnce Send + Sync
    callback: Arc<Mutex<Option<NodeInfoCallback>>>,
    created: Instant,
}

// CallbackInfo is automatically Send + Sync because:
// - Arc<Mutex<Option<NodeInfoCallback>>> is Send + Sync
// - Instant is Send + Sync
// No unsafe impl needed

pub struct NodeInfo {
    my_nodeinfo: Arc<RwLock<JsonValue>>,
    callbacks: Arc<RwLock<HashMap<[u8; 32], CallbackInfo>>>,
    send_tx: mpsc::Sender<(Vec<u8>, [u8; 32])>,
}

impl NodeInfo {
    pub fn new(send_tx: mpsc::Sender<(Vec<u8>, [u8; 32])>) -> Self {
        let nodeinfo = Self {
            my_nodeinfo: Arc::new(RwLock::new(json!({}))),
            callbacks: Arc::new(RwLock::new(HashMap::new())),
            send_tx,
        };

        // Start cleanup task
        nodeinfo.start_cleanup_task();

        nodeinfo
    }

    fn start_cleanup_task(&self) {
        let callbacks = Arc::clone(&self.callbacks);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;

                let now = Instant::now();
                {
                    let mut map = callbacks.write().await;
                    map.retain(|_, info| now.duration_since(info.created) < CALLBACK_TIMEOUT);
                }
            }
        });
    }

    pub async fn set_nodeinfo(&self, mut given: JsonValue, privacy: bool) -> Result<()> {
        // Create new nodeinfo based on provided data
        let mut nodeinfo = if let Some(obj) = given.as_object_mut() {
            obj.clone()
        } else {
            return Err(anyhow::anyhow!("NodeInfo must be a JSON object"));
        };

        // Add system information if privacy is not enabled
        if !privacy {
            nodeinfo.insert("buildname".to_string(), json!("yggdrasil-rust"));
            nodeinfo.insert("buildversion".to_string(), json!(env!("CARGO_PKG_VERSION")));
            nodeinfo.insert("buildplatform".to_string(), json!(std::env::consts::OS));
            nodeinfo.insert("buildarch".to_string(), json!(std::env::consts::ARCH));
        }

        // Serialize to check size
        let serialized = serde_json::to_vec(&nodeinfo)?;
        if serialized.len() > MAX_NODEINFO_SIZE {
            return Err(anyhow::anyhow!(
                "NodeInfo exceeds max length of {} bytes",
                MAX_NODEINFO_SIZE
            ));
        }

        // Store the nodeinfo
        let mut my_info = self.my_nodeinfo.write().await;
        *my_info = JsonValue::Object(nodeinfo.into_iter().collect());

        Ok(())
    }

    pub async fn get_nodeinfo(&self) -> JsonValue {
        self.my_nodeinfo.read().await.clone()
    }

    pub async fn send_request<F>(&self, key: [u8; 32], callback: F) -> Result<()>
    where
        F: FnOnce(JsonValue) + Send + 'static,
    {
        // Add callback
        let mut callbacks = self.callbacks.write().await;
        callbacks.remove(&key); // Remove any existing callback
        callbacks.insert(
            key,
            CallbackInfo {
                callback: Arc::new(Mutex::new(Some(Box::new(callback)))),
                created: Instant::now(),
            },
        );
        drop(callbacks);

        // Send request packet
        let packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_NODEINFO_REQUEST];
        self.send_tx
            .send((packet, key))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send NodeInfo request: {}", e))
    }

    pub async fn handle_request(&self, from_key: [u8; 32]) -> Result<()> {
        // Get current nodeinfo
        let nodeinfo = self.my_nodeinfo.read().await;
        let nodeinfo_bytes = serde_json::to_vec(&*nodeinfo)?;
        drop(nodeinfo);

        // Send response
        let mut packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_NODEINFO_RESPONSE];
        packet.extend_from_slice(&nodeinfo_bytes);

        self.send_tx
            .send((packet, from_key))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send NodeInfo response: {}", e))
    }

    pub async fn handle_response(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        // Parse nodeinfo from response
        let nodeinfo: JsonValue = serde_json::from_slice(data)?;

        // Find and execute callback
        let mut callbacks = self.callbacks.write().await;
        if let Some(info) = callbacks.remove(&from_key) {
            drop(callbacks);
            // Take the callback out of the Arc<Mutex<Option<>>>
            if let Some(callback) = info.callback.lock().await.take() {
                callback(nodeinfo);
            }
        }

        Ok(())
    }
}

// Admin API request/response types
#[derive(Debug, Serialize, Deserialize)]
pub struct GetNodeInfoRequest {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetNodeInfoResponse {
    #[serde(flatten)]
    pub data: HashMap<String, JsonValue>,
}

// Helper function to send NodeInfo request with timeout
pub async fn get_nodeinfo_with_timeout(nodeinfo: &NodeInfo, key: [u8; 32]) -> Result<JsonValue> {
    let (tx, mut rx) = mpsc::channel(1);

    nodeinfo
        .send_request(key, move |data| {
            tokio::spawn(async move {
                let _ = tx.send(data).await;
            });
        })
        .await?;

    match timeout(Duration::from_secs(6), rx.recv()).await {
        Ok(Some(data)) => Ok(data),
        Ok(None) => Err(anyhow::anyhow!("Channel closed")),
        Err(_) => Err(anyhow::anyhow!("Request timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nodeinfo_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        let info = nodeinfo.get_nodeinfo().await;
        assert!(info.is_object());
    }

    #[tokio::test]
    async fn test_set_nodeinfo_with_privacy() {
        let (tx, _rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        let test_info = json!({
            "name": "test-node",
            "location": "test-location"
        });

        nodeinfo
            .set_nodeinfo(test_info.clone(), true)
            .await
            .unwrap();

        let stored = nodeinfo.get_nodeinfo().await;
        assert_eq!(stored["name"], "test-node");
        assert_eq!(stored["location"], "test-location");

        // Should not have build info when privacy is enabled
        assert!(stored.get("buildname").is_none());
    }

    #[tokio::test]
    async fn test_set_nodeinfo_without_privacy() {
        let (tx, _rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        let test_info = json!({
            "name": "test-node"
        });

        nodeinfo
            .set_nodeinfo(test_info.clone(), false)
            .await
            .unwrap();

        let stored = nodeinfo.get_nodeinfo().await;
        assert_eq!(stored["name"], "test-node");

        // Should have build info when privacy is disabled
        assert!(stored.get("buildname").is_some());
        assert!(stored.get("buildversion").is_some());
        assert!(stored.get("buildplatform").is_some());
        assert!(stored.get("buildarch").is_some());
    }

    #[tokio::test]
    async fn test_nodeinfo_size_limit() {
        let (tx, _rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        // Create a very large nodeinfo (> 16KB)
        let large_string = "x".repeat(20000);
        let test_info = json!({
            "data": large_string
        });

        let result = nodeinfo.set_nodeinfo(test_info, true).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds max length"));
    }

    #[tokio::test]
    async fn test_send_nodeinfo_request() {
        let (tx, mut rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        let key = [1u8; 32];

        nodeinfo
            .send_request(key, |_data| {
                // Callback
            })
            .await
            .unwrap();

        // Verify packet was sent
        let (packet, to_key) = rx.recv().await.unwrap();
        assert_eq!(to_key, key);
        assert_eq!(packet[0], TYPE_SESSION_PROTO);
        assert_eq!(packet[1], TYPE_PROTO_NODEINFO_REQUEST);
    }

    #[tokio::test]
    async fn test_handle_nodeinfo_request() {
        let (tx, mut rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        // Set some nodeinfo first
        let test_info = json!({
            "name": "responder-node"
        });
        nodeinfo.set_nodeinfo(test_info, true).await.unwrap();

        let from_key = [2u8; 32];
        nodeinfo.handle_request(from_key).await.unwrap();

        // Verify response packet was sent
        let (packet, to_key) = rx.recv().await.unwrap();
        assert_eq!(to_key, from_key);
        assert_eq!(packet[0], TYPE_SESSION_PROTO);
        assert_eq!(packet[1], TYPE_PROTO_NODEINFO_RESPONSE);

        // Parse the nodeinfo from packet
        let info: JsonValue = serde_json::from_slice(&packet[2..]).unwrap();
        assert_eq!(info["name"], "responder-node");
    }

    #[tokio::test]
    async fn test_handle_nodeinfo_response() {
        let (tx, _rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        let key = [3u8; 32];
        let (callback_tx, mut callback_rx) = mpsc::channel(1);

        // Register request with async-safe callback
        let callback_tx_clone = callback_tx.clone();
        nodeinfo
            .send_request(key, move |data| {
                tokio::spawn(async move {
                    let _ = callback_tx_clone.send(data).await;
                });
            })
            .await
            .unwrap();

        // Simulate response
        let response_info = json!({
            "name": "remote-node",
            "version": "1.0"
        });
        let response_data = serde_json::to_vec(&response_info).unwrap();

        nodeinfo.handle_response(key, &response_data).await.unwrap();

        // Verify callback was called with correct data
        let received = timeout(Duration::from_secs(1), callback_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received["name"], "remote-node");
        assert_eq!(received["version"], "1.0");

        // Verify callback was removed
        assert_eq!(nodeinfo.callbacks.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_nodeinfo_must_be_object() {
        let (tx, _rx) = mpsc::channel(10);
        let nodeinfo = NodeInfo::new(tx);

        // Try to set non-object nodeinfo
        let invalid_info = json!("not an object");
        let result = nodeinfo.set_nodeinfo(invalid_info, true).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be a JSON object"));
    }
}
