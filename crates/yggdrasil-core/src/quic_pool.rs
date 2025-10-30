use anyhow::Result;
use quinn::{Connection, SendStream, RecvStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use log::{info, debug};

/// QUIC connection pool configuration
#[derive(Debug, Clone)]
pub struct QuicPoolConfig {
    /// Maximum connections per peer
    pub max_connections_per_peer: usize,
    /// Maximum concurrent streams per connection
    pub max_streams_per_connection: usize,
    /// Connection idle timeout (seconds)
    pub idle_timeout_secs: u64,
}

impl Default for QuicPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_peer: 4,
            max_streams_per_connection: 100,
            idle_timeout_secs: 300,
        }
    }
}

/// Pooled QUIC connection with stream management
pub struct PooledConnection {
    connection: Connection,
    /// Semaphore to limit concurrent streams
    stream_semaphore: Arc<Semaphore>,
    /// Active stream count
    active_streams: Arc<RwLock<usize>>,
}

impl PooledConnection {
    pub fn new(connection: Connection, max_streams: usize) -> Self {
        Self {
            connection,
            stream_semaphore: Arc::new(Semaphore::new(max_streams)),
            active_streams: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Open a bidirectional stream with flow control
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        // Acquire permit from semaphore (blocks if max streams reached)
        let _permit = self.stream_semaphore.acquire().await
            .map_err(|e| anyhow::anyhow!("Failed to acquire stream permit: {}", e))?;
        
        // Increment active stream count
        {
            let mut count = self.active_streams.write().await;
            *count += 1;
        }
        
        // Open stream
        let (send, recv) = self.connection.open_bi().await
            .map_err(|e| anyhow::anyhow!("Failed to open bidirectional stream: {}", e))?;
        
        debug!("Opened bidirectional stream (active: {})", *self.active_streams.read().await);
        
        Ok((send, recv))
    }
    
    /// Accept a bidirectional stream
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream)> {
        let (send, recv) = self.connection.accept_bi().await
            .map_err(|e| anyhow::anyhow!("Failed to accept bidirectional stream: {}", e))?;
        
        // Increment active stream count
        {
            let mut count = self.active_streams.write().await;
            *count += 1;
        }
        
        debug!("Accepted bidirectional stream (active: {})", *self.active_streams.read().await);
        
        Ok((send, recv))
    }
    
    /// Get active stream count
    pub async fn active_stream_count(&self) -> usize {
        *self.active_streams.read().await
    }
    
    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
    
    /// Get remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }
}

/// QUIC connection pool for managing multiple connections to peers
pub struct QuicPool {
    /// Pool configuration
    config: QuicPoolConfig,
    /// Connections indexed by peer address
    connections: Arc<RwLock<HashMap<SocketAddr, Vec<Arc<PooledConnection>>>>>,
}

impl QuicPool {
    /// Create a new QUIC connection pool
    pub fn new(config: QuicPoolConfig) -> Self {
        info!("Creating QUIC connection pool with config: {:?}", config);
        Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Add a connection to the pool
    pub async fn add_connection(&self, addr: SocketAddr, connection: Connection) {
        let pooled = Arc::new(PooledConnection::new(
            connection,
            self.config.max_streams_per_connection,
        ));
        
        let mut connections = self.connections.write().await;
        let peer_connections = connections.entry(addr).or_insert_with(Vec::new);
        
        // Limit connections per peer
        if peer_connections.len() >= self.config.max_connections_per_peer {
            debug!("Removing oldest connection for {} (max {} reached)", 
                   addr, self.config.max_connections_per_peer);
            peer_connections.remove(0);
        }
        
        peer_connections.push(pooled);
        info!("Added QUIC connection to pool for {} (total: {})", addr, peer_connections.len());
    }
    
    /// Get a connection from the pool (round-robin selection)
    pub async fn get_connection(&self, addr: &SocketAddr) -> Option<Arc<PooledConnection>> {
        let connections = self.connections.read().await;
        
        if let Some(peer_connections) = connections.get(addr) {
            // Find connection with lowest active stream count
            let best = peer_connections.iter()
                .filter(|c| !c.is_closed())
                .min_by_key(|c| {
                    // Use blocking read in async context (safe because we hold read lock)
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(c.active_stream_count())
                    })
                });
            
            if let Some(conn) = best {
                debug!("Selected QUIC connection to {} with {} active streams", 
                       addr, tokio::task::block_in_place(|| {
                           tokio::runtime::Handle::current().block_on(conn.active_stream_count())
                       }));
                return Some(Arc::clone(conn));
            }
        }
        
        None
    }
    
    /// Remove a connection from the pool
    pub async fn remove_connection(&self, addr: &SocketAddr) {
        let mut connections = self.connections.write().await;
        
        if let Some(peer_connections) = connections.get_mut(addr) {
            peer_connections.retain(|c| !c.is_closed());
            
            if peer_connections.is_empty() {
                connections.remove(addr);
                info!("Removed all QUIC connections for {}", addr);
            }
        }
    }
    
    /// Cleanup closed connections
    pub async fn cleanup(&self) {
        let mut connections = self.connections.write().await;
        let mut to_remove = Vec::new();
        
        for (addr, peer_connections) in connections.iter_mut() {
            peer_connections.retain(|c| !c.is_closed());
            
            if peer_connections.is_empty() {
                to_remove.push(*addr);
            }
        }
        
        for addr in to_remove {
            connections.remove(&addr);
            debug!("Cleaned up empty connection pool for {}", addr);
        }
    }
    
    /// Get pool statistics
    pub async fn get_stats(&self) -> QuicPoolStats {
        let connections = self.connections.read().await;
        
        let total_connections = connections.values()
            .map(|v| v.len())
            .sum();
        
        let total_active_streams = connections.values()
            .flat_map(|v| v.iter())
            .map(|c| {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(c.active_stream_count())
                })
            })
            .sum();
        
        QuicPoolStats {
            total_peers: connections.len(),
            total_connections,
            total_active_streams,
        }
    }
}

/// QUIC pool statistics
#[derive(Debug, Clone)]
pub struct QuicPoolStats {
    pub total_peers: usize,
    pub total_connections: usize,
    pub total_active_streams: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pool_config_default() {
        let config = QuicPoolConfig::default();
        assert_eq!(config.max_connections_per_peer, 4);
        assert_eq!(config.max_streams_per_connection, 100);
        assert_eq!(config.idle_timeout_secs, 300);
    }
    
    #[tokio::test]
    async fn test_pool_creation() {
        let config = QuicPoolConfig::default();
        let pool = QuicPool::new(config);
        
        let stats = pool.get_stats().await;
        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.total_connections, 0);
    }
}
