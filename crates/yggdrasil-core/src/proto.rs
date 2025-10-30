use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::timeout;

// In-band packet types (matching types.go)
pub const TYPE_SESSION_DUMMY: u8 = 0;
pub const TYPE_SESSION_TRAFFIC: u8 = 1;
pub const TYPE_SESSION_PROTO: u8 = 2;

// Protocol packet types (matching types.go)
pub const TYPE_PROTO_DUMMY: u8 = 0;
pub const TYPE_PROTO_NODEINFO_REQUEST: u8 = 1;
pub const TYPE_PROTO_NODEINFO_RESPONSE: u8 = 2;
pub const TYPE_PROTO_TREE_ANNOUNCEMENT: u8 = 3; // Tree announcement gossip
pub const TYPE_PROTO_BLOOM_FILTER: u8 = 4; // Bloom filter exchange
pub const TYPE_PROTO_LOOKUP_REQUEST: u8 = 5; // Node lookup request
pub const TYPE_PROTO_LOOKUP_RESPONSE: u8 = 6; // Node lookup response
pub const TYPE_PROTO_DEBUG: u8 = 255;

// Debug protocol types
pub const TYPE_DEBUG_DUMMY: u8 = 0;
pub const TYPE_DEBUG_GET_SELF_REQUEST: u8 = 1;
pub const TYPE_DEBUG_GET_SELF_RESPONSE: u8 = 2;
pub const TYPE_DEBUG_GET_PEERS_REQUEST: u8 = 3;
pub const TYPE_DEBUG_GET_PEERS_RESPONSE: u8 = 4;
pub const TYPE_DEBUG_GET_TREE_REQUEST: u8 = 5;
pub const TYPE_DEBUG_GET_TREE_RESPONSE: u8 = 6;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(6);

type DebugCallback = Box<dyn FnOnce(Vec<u8>) + Send + 'static>;

struct RequestInfo {
    // Use Arc<Mutex<Option<>>> to make FnOnce Send + Sync
    callback: Arc<Mutex<Option<DebugCallback>>>,
    created: Instant,
}

// RequestInfo is automatically Send + Sync because:
// - Arc<Mutex<Option<DebugCallback>>> is Send + Sync
// - Instant is Send + Sync
// No unsafe impl needed

pub struct ProtoHandler {
    self_requests: Arc<RwLock<HashMap<[u8; 32], RequestInfo>>>,
    peers_requests: Arc<RwLock<HashMap<[u8; 32], RequestInfo>>>,
    tree_requests: Arc<RwLock<HashMap<[u8; 32], RequestInfo>>>,
    lookup_requests: Arc<RwLock<HashMap<([u8; 32], [u8; 32]), RequestInfo>>>, // (from_key, target_key) -> callback
    send_tx: mpsc::Sender<(Vec<u8>, [u8; 32])>,
}

impl ProtoHandler {
    pub fn new(send_tx: mpsc::Sender<(Vec<u8>, [u8; 32])>) -> Self {
        let handler = Self {
            self_requests: Arc::new(RwLock::new(HashMap::new())),
            peers_requests: Arc::new(RwLock::new(HashMap::new())),
            tree_requests: Arc::new(RwLock::new(HashMap::new())),
            lookup_requests: Arc::new(RwLock::new(HashMap::new())),
            send_tx,
        };

        // Start cleanup task
        handler.start_cleanup_task();

        handler
    }

    fn start_cleanup_task(&self) {
        let self_reqs = Arc::clone(&self.self_requests);
        let peers_reqs = Arc::clone(&self.peers_requests);
        let tree_reqs = Arc::clone(&self.tree_requests);
        let lookup_reqs = Arc::clone(&self.lookup_requests);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;

                let now = Instant::now();

                // Clean up expired self requests
                {
                    let mut self_map = self_reqs.write().await;
                    self_map.retain(|_, info| now.duration_since(info.created) < REQUEST_TIMEOUT);
                }

                // Clean up expired peers requests
                {
                    let mut peers_map = peers_reqs.write().await;
                    peers_map.retain(|_, info| now.duration_since(info.created) < REQUEST_TIMEOUT);
                }

                // Clean up expired tree requests
                {
                    let mut tree_map = tree_reqs.write().await;
                    tree_map.retain(|_, info| now.duration_since(info.created) < REQUEST_TIMEOUT);
                }

                // Clean up expired lookup requests
                {
                    let mut lookup_map = lookup_reqs.write().await;
                    lookup_map.retain(|_, info| now.duration_since(info.created) < REQUEST_TIMEOUT);
                }
            }
        });
    }

    pub async fn handle_proto(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        match data[0] {
            TYPE_PROTO_DUMMY => Ok(()),
            TYPE_PROTO_NODEINFO_REQUEST => {
                // Forward to nodeinfo handler (to be implemented)
                log::debug!("Received NodeInfo request from {:?}", hex::encode(from_key));
                Ok(())
            }
            TYPE_PROTO_NODEINFO_RESPONSE => {
                // Forward to nodeinfo handler (to be implemented)
                log::debug!("Received NodeInfo response from {:?}", hex::encode(from_key));
                Ok(())
            }
            TYPE_PROTO_TREE_ANNOUNCEMENT => {
                // Tree announcements are handled directly by Core since it owns SpanningTree
                // This is just a marker - actual handling happens in Core::handle_session_packet
                log::debug!("Received tree announcement from {:?}", hex::encode(from_key));
                Ok(())
            }
            TYPE_PROTO_BLOOM_FILTER => {
                if data.len() > 1 {
                    self.handle_bloom_filter_update(from_key, &data[1..]).await
                } else {
                    Ok(())
                }
            }
            TYPE_PROTO_LOOKUP_REQUEST => {
                if data.len() > 1 {
                    self.handle_lookup_request(from_key, &data[1..]).await
                } else {
                    Ok(())
                }
            }
            TYPE_PROTO_LOOKUP_RESPONSE => {
                if data.len() > 1 {
                    self.handle_lookup_response(from_key, &data[1..]).await
                } else {
                    Ok(())
                }
            }
            TYPE_PROTO_DEBUG => {
                if data.len() > 1 {
                    self.handle_debug(from_key, &data[1..]).await
                } else {
                    Ok(())
                }
            }
            _ => {
                log::warn!("Unknown protocol type: {}", data[0]);
                Ok(())
            }
        }
    }

    async fn handle_debug(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        match data[0] {
            TYPE_DEBUG_DUMMY => Ok(()),
            TYPE_DEBUG_GET_SELF_REQUEST => self.handle_get_self_request(from_key).await,
            TYPE_DEBUG_GET_SELF_RESPONSE => {
                if data.len() > 1 {
                    self.handle_get_self_response(from_key, &data[1..]).await
                } else {
                    Ok(())
                }
            }
            TYPE_DEBUG_GET_PEERS_REQUEST => self.handle_get_peers_request(from_key).await,
            TYPE_DEBUG_GET_PEERS_RESPONSE => {
                if data.len() > 1 {
                    self.handle_get_peers_response(from_key, &data[1..]).await
                } else {
                    Ok(())
                }
            }
            TYPE_DEBUG_GET_TREE_REQUEST => self.handle_get_tree_request(from_key).await,
            TYPE_DEBUG_GET_TREE_RESPONSE => {
                if data.len() > 1 {
                    self.handle_get_tree_response(from_key, &data[1..]).await
                } else {
                    Ok(())
                }
            }
            _ => {
                log::warn!("Unknown debug protocol type: {}", data[0]);
                Ok(())
            }
        }
    }

    async fn send_debug(&self, to_key: [u8; 32], debug_type: u8, data: &[u8]) -> Result<()> {
        let mut packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_DEBUG, debug_type];
        packet.extend_from_slice(data);
        self.send_tx
            .send((packet, to_key))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send debug packet: {}", e))
    }

    // Get Self methods
    pub async fn send_get_self_request<F>(&self, key: [u8; 32], callback: F) -> Result<()>
    where
        F: FnOnce(Vec<u8>) + Send + 'static,
    {
        let mut requests = self.self_requests.write().await;
        requests.remove(&key); // Remove any existing request
        requests.insert(
            key,
            RequestInfo {
                callback: Arc::new(Mutex::new(Some(Box::new(callback)))),
                created: Instant::now(),
            },
        );
        drop(requests);

        self.send_debug(key, TYPE_DEBUG_GET_SELF_REQUEST, &[])
            .await
    }

    async fn handle_get_self_request(&self, from_key: [u8; 32]) -> Result<()> {
        // Placeholder: In real implementation, this would query Core
        let response = serde_json::json!({
            "key": hex::encode(from_key),
            "routing_entries": 0,
        });

        let response_data = serde_json::to_vec(&response)?;
        self.send_debug(from_key, TYPE_DEBUG_GET_SELF_RESPONSE, &response_data)
            .await
    }

    async fn handle_get_self_response(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        let mut requests = self.self_requests.write().await;
        if let Some(info) = requests.remove(&from_key) {
            drop(requests);
            // Take the callback out of the Arc<Mutex<Option<>>>
            if let Some(callback) = info.callback.lock().await.take() {
                callback(data.to_vec());
            }
        }
        Ok(())
    }

    // Get Peers methods
    pub async fn send_get_peers_request<F>(&self, key: [u8; 32], callback: F) -> Result<()>
    where
        F: FnOnce(Vec<u8>) + Send + 'static,
    {
        let mut requests = self.peers_requests.write().await;
        requests.remove(&key);
        requests.insert(
            key,
            RequestInfo {
                callback: Arc::new(Mutex::new(Some(Box::new(callback)))),
                created: Instant::now(),
            },
        );
        drop(requests);

        self.send_debug(key, TYPE_DEBUG_GET_PEERS_REQUEST, &[])
            .await
    }

    async fn handle_get_peers_request(&self, from_key: [u8; 32]) -> Result<()> {
        // Placeholder: In real implementation, this would query Core for peer list
        // Return empty peer list for now
        let response_data = Vec::new();
        self.send_debug(from_key, TYPE_DEBUG_GET_PEERS_RESPONSE, &response_data)
            .await
    }

    async fn handle_get_peers_response(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        let mut requests = self.peers_requests.write().await;
        if let Some(info) = requests.remove(&from_key) {
            drop(requests);
            // Take the callback out of the Arc<Mutex<Option<>>>
            if let Some(callback) = info.callback.lock().await.take() {
                callback(data.to_vec());
            }
        }
        Ok(())
    }

    // Get Tree methods
    pub async fn send_get_tree_request<F>(&self, key: [u8; 32], callback: F) -> Result<()>
    where
        F: FnOnce(Vec<u8>) + Send + 'static,
    {
        let mut requests = self.tree_requests.write().await;
        requests.remove(&key);
        requests.insert(
            key,
            RequestInfo {
                callback: Arc::new(Mutex::new(Some(Box::new(callback)))),
                created: Instant::now(),
            },
        );
        drop(requests);

        self.send_debug(key, TYPE_DEBUG_GET_TREE_REQUEST, &[])
            .await
    }

    async fn handle_get_tree_request(&self, from_key: [u8; 32]) -> Result<()> {
        // Placeholder: In real implementation, this would query Core for tree info
        // Return empty tree for now
        let response_data = Vec::new();
        self.send_debug(from_key, TYPE_DEBUG_GET_TREE_RESPONSE, &response_data)
            .await
    }

    async fn handle_get_tree_response(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        let mut requests = self.tree_requests.write().await;
        if let Some(info) = requests.remove(&from_key) {
            drop(requests);
            // Take the callback out of the Arc<Mutex<Option<>>>
            if let Some(callback) = info.callback.lock().await.take() {
                callback(data.to_vec());
            }
        }
        Ok(())
    }

    // Bloom Filter Exchange methods
    pub async fn send_bloom_filter_update(&self, to_key: [u8; 32], filter_data: &[u8]) -> Result<()> {
        let mut packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_BLOOM_FILTER];
        packet.extend_from_slice(filter_data);
        self.send_tx
            .send((packet, to_key))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send bloom filter: {}", e))
    }

    async fn handle_bloom_filter_update(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        // Bloom filter format: [filter_bytes (1024)]
        if data.len() < 1024 {
            log::warn!("Invalid bloom filter size from {:?}: {} bytes", hex::encode(from_key), data.len());
            return Ok(());
        }

        log::debug!("Received bloom filter update from {:?}", hex::encode(from_key));
        
        // This will be handled by Core which has access to LookupManager
        // For now, just log it
        Ok(())
    }

    // Lookup Request/Response methods
    pub async fn send_lookup_request<F>(
        &self,
        to_key: [u8; 32],
        target_key: [u8; 32],
        callback: F,
    ) -> Result<()>
    where
        F: FnOnce(Option<[u8; 32]>) + Send + 'static,
    {
        let mut requests = self.lookup_requests.write().await;
        requests.remove(&(to_key, target_key));
        
        // Convert the Option<[u8; 32]> callback to Vec<u8> callback
        let wrapped_callback = Box::new(move |data: Vec<u8>| {
            if data.len() >= 32 {
                let mut found_key = [0u8; 32];
                found_key.copy_from_slice(&data[..32]);
                callback(Some(found_key));
            } else {
                callback(None);
            }
        });
        
        requests.insert(
            (to_key, target_key),
            RequestInfo {
                callback: Arc::new(Mutex::new(Some(wrapped_callback))),
                created: Instant::now(),
            },
        );
        drop(requests);

        // Packet format: [TYPE_SESSION_PROTO][TYPE_PROTO_LOOKUP_REQUEST][target_key(32)]
        let mut packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_LOOKUP_REQUEST];
        packet.extend_from_slice(&target_key);
        
        self.send_tx
            .send((packet, to_key))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send lookup request: {}", e))
    }

    async fn handle_lookup_request(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        if data.len() < 32 {
            log::warn!("Invalid lookup request from {:?}: {} bytes", hex::encode(from_key), data.len());
            return Ok(());
        }

        let mut target_key = [0u8; 32];
        target_key.copy_from_slice(&data[..32]);

        log::debug!(
            "Received lookup request from {:?} for target {:?}",
            hex::encode(from_key),
            hex::encode(target_key)
        );

        // This will be handled by Core which has access to LookupManager
        // For now, send empty response (not found)
        self.send_lookup_response(from_key, None).await
    }

    pub async fn send_lookup_response(&self, to_key: [u8; 32], found_key: Option<[u8; 32]>) -> Result<()> {
        // Packet format: [TYPE_SESSION_PROTO][TYPE_PROTO_LOOKUP_RESPONSE][found_key(32) or empty]
        let mut packet = vec![TYPE_SESSION_PROTO, TYPE_PROTO_LOOKUP_RESPONSE];
        
        if let Some(key) = found_key {
            packet.extend_from_slice(&key);
        }

        self.send_tx
            .send((packet, to_key))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send lookup response: {}", e))
    }

    async fn handle_lookup_response(&self, from_key: [u8; 32], data: &[u8]) -> Result<()> {
        log::debug!(
            "Received lookup response from {:?}, data len: {}",
            hex::encode(from_key),
            data.len()
        );

        // Find the matching request by iterating through all pending requests
        let mut requests = self.lookup_requests.write().await;
        let mut found_request = None;
        
        for ((req_to_key, _target_key), _info) in requests.iter() {
            if req_to_key == &from_key {
                found_request = Some((*req_to_key, *_target_key));
                break;
            }
        }

        if let Some(key_pair) = found_request {
            if let Some(info) = requests.remove(&key_pair) {
                drop(requests);
                
                // Take the callback out of the Arc<Mutex<Option<>>>
                if let Some(callback) = info.callback.lock().await.take() {
                    callback(data.to_vec());
                }
            }
        }

        Ok(())
    }
}

// Admin API request/response types
#[derive(Debug, Serialize, Deserialize)]
pub struct DebugGetSelfRequest {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugGetSelfResponse {
    #[serde(flatten)]
    pub data: HashMap<String, JsonValue>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugGetPeersRequest {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugGetPeersResponse {
    #[serde(flatten)]
    pub data: HashMap<String, JsonValue>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugGetTreeRequest {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugGetTreeResponse {
    #[serde(flatten)]
    pub data: HashMap<String, JsonValue>,
}

// Helper function to send protocol request with timeout
pub async fn send_proto_request_with_timeout<F>(
    handler: &ProtoHandler,
    key: [u8; 32],
    request_type: &str,
    callback: F,
) -> Result<JsonValue>
where
    F: FnOnce(Vec<u8>) + Send + Sync + 'static,
{
    let (tx, mut rx) = mpsc::channel(1);

    let wrapped_callback = move |data: Vec<u8>| {
        callback(data.clone());
        let _ = tx.blocking_send(data);
    };

    match request_type {
        "get_self" => handler.send_get_self_request(key, wrapped_callback).await?,
        "get_peers" => handler.send_get_peers_request(key, wrapped_callback).await?,
        "get_tree" => handler.send_get_tree_request(key, wrapped_callback).await?,
        _ => return Err(anyhow::anyhow!("Unknown request type")),
    }

    match timeout(CALLBACK_TIMEOUT, rx.recv()).await {
        Ok(Some(data)) => {
            let value: JsonValue = serde_json::from_slice(&data)?;
            Ok(value)
        }
        Ok(None) => Err(anyhow::anyhow!("Channel closed")),
        Err(_) => Err(anyhow::anyhow!("Request timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proto_handler_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);

        assert_eq!(handler.self_requests.read().await.len(), 0);
        assert_eq!(handler.peers_requests.read().await.len(), 0);
        assert_eq!(handler.tree_requests.read().await.len(), 0);
        assert_eq!(handler.lookup_requests.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_empty_proto() {
        let (tx, _rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let key = [0u8; 32];

        let result = handler.handle_proto(key, &[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_dummy_proto() {
        let (tx, _rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let key = [0u8; 32];

        let result = handler.handle_proto(key, &[TYPE_PROTO_DUMMY]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_get_self_request() {
        let (tx, mut rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let key = [1u8; 32];

        let result = handler
            .send_get_self_request(key, |_data| {
                // Callback
            })
            .await;

        assert!(result.is_ok());

        // Verify packet was sent
        let (packet, to_key) = rx.recv().await.unwrap();
        assert_eq!(to_key, key);
        assert_eq!(packet[0], TYPE_SESSION_PROTO);
        assert_eq!(packet[1], TYPE_PROTO_DEBUG);
        assert_eq!(packet[2], TYPE_DEBUG_GET_SELF_REQUEST);
    }

    #[tokio::test]
    async fn test_request_cleanup() {
        let (tx, _rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let key = [2u8; 32];

        // Add a request
        handler
            .send_get_self_request(key, |_data| {})
            .await
            .unwrap();

        assert_eq!(handler.self_requests.read().await.len(), 1);

        // Wait for cleanup (in real scenario, this would take 60 seconds)
        // For testing, we manually expire the request
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(handler.self_requests.read().await.len(), 1);
    }

    #[tokio::test]
    async fn test_handle_get_self_response() {
        let (tx, _rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let key = [3u8; 32];

        let (callback_tx, mut callback_rx) = mpsc::channel(1);

        // Register request with async-safe callback
        let callback_tx_clone = callback_tx.clone();
        handler
            .send_get_self_request(key, move |data| {
                tokio::spawn(async move {
                    let _ = callback_tx_clone.send(data).await;
                });
            })
            .await
            .unwrap();

        // Simulate response
        let response_data = b"test response";
        handler
            .handle_get_self_response(key, response_data)
            .await
            .unwrap();

        // Verify callback was called
        let received = timeout(Duration::from_secs(1), callback_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, response_data);

        // Verify request was removed
        assert_eq!(handler.self_requests.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_send_bloom_filter_update() {
        let (tx, mut rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let key = [5u8; 32];
        let filter_data = vec![0u8; 1024]; // 1024-byte bloom filter

        let result = handler.send_bloom_filter_update(key, &filter_data).await;
        assert!(result.is_ok());

        // Verify packet was sent
        let (packet, to_key) = rx.recv().await.unwrap();
        assert_eq!(to_key, key);
        assert_eq!(packet[0], TYPE_SESSION_PROTO);
        assert_eq!(packet[1], TYPE_PROTO_BLOOM_FILTER);
        assert_eq!(packet.len(), 2 + 1024);
    }

    #[tokio::test]
    async fn test_handle_bloom_filter_update() {
        let (tx, _rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let key = [6u8; 32];
        let filter_data = vec![0u8; 1024];

        let result = handler.handle_bloom_filter_update(key, &filter_data).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_lookup_request() {
        let (tx, mut rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let to_key = [7u8; 32];
        let target_key = [8u8; 32];

        let result = handler
            .send_lookup_request(to_key, target_key, |_result| {
                // Callback
            })
            .await;

        assert!(result.is_ok());

        // Verify packet was sent
        let (packet, sent_to_key) = rx.recv().await.unwrap();
        assert_eq!(sent_to_key, to_key);
        assert_eq!(packet[0], TYPE_SESSION_PROTO);
        assert_eq!(packet[1], TYPE_PROTO_LOOKUP_REQUEST);
        assert_eq!(packet.len(), 2 + 32);
        assert_eq!(&packet[2..34], &target_key);
    }

    #[tokio::test]
    async fn test_lookup_request_response_flow() {
        let (tx, mut rx) = mpsc::channel(10);
        let handler = ProtoHandler::new(tx);
        let to_key = [9u8; 32];
        let target_key = [10u8; 32];
        let found_key = [11u8; 32];

        let (callback_tx, mut callback_rx) = mpsc::channel(1);

        // Send request
        let callback_tx_clone = callback_tx.clone();
        handler
            .send_lookup_request(to_key, target_key, move |result| {
                tokio::spawn(async move {
                    let _ = callback_tx_clone.send(result).await;
                });
            })
            .await
            .unwrap();

        // Consume the request packet
        let _ = rx.recv().await.unwrap();

        // Simulate response
        let mut response_data = found_key.to_vec();
        handler
            .handle_lookup_response(to_key, &response_data)
            .await
            .unwrap();

        // Verify callback was called with found key
        let received = timeout(Duration::from_secs(1), callback_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, Some(found_key));
    }
}
