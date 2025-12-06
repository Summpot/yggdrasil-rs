//! Core Yggdrasil node implementation.

use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;
use yggdrasil_address::{Address, Subnet};
use yggdrasil_config::NodeConfig;
use yggdrasil_session::SessionManager;
use yggdrasil_types::{PrivateKey, PublicKey};

/// Configuration for the Core.
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Private key for this node.
    pub private_key: PrivateKey,
}

/// Errors that can occur when starting or running the core.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("already started")]
    AlreadyStarted,
    #[error("not started")]
    NotStarted,
}

/// The core Yggdrasil node.
pub struct Core {
    /// Our private key.
    private_key: PrivateKey,
    /// Our public key.
    public_key: PublicKey,
    /// Our IPv6 address.
    address: Address,
    /// Our subnet.
    subnet: Subnet,
    /// Session manager.
    sessions: Arc<SessionManager>,
    /// Whether the core is running.
    running: RwLock<bool>,
}

impl Core {
    /// Create a new Core from a NodeConfig.
    pub fn new(config: &NodeConfig) -> Result<Self, CoreError> {
        let private_key = config
            .get_private_key()
            .map_err(|e| CoreError::Config(e.to_string()))?;

        Self::with_private_key(private_key)
    }

    /// Create a new Core with a specific private key.
    pub fn with_private_key(private_key: PrivateKey) -> Result<Self, CoreError> {
        let public_key = private_key.public_key();
        let address = yggdrasil_address::addr_for_key(&public_key).ok_or_else(|| {
            CoreError::Config("Failed to derive address from public key".to_string())
        })?;
        let subnet = yggdrasil_address::subnet_for_key(&public_key).ok_or_else(|| {
            CoreError::Config("Failed to derive subnet from public key".to_string())
        })?;

        let sessions = Arc::new(SessionManager::new(private_key.clone()));

        Ok(Self {
            private_key,
            public_key,
            address,
            subnet,
            sessions,
            running: RwLock::new(false),
        })
    }

    /// Get the node's private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Get the node's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the node's IPv6 address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the node's subnet.
    pub fn subnet(&self) -> &Subnet {
        &self.subnet
    }

    /// Get the session manager.
    pub fn sessions(&self) -> &Arc<SessionManager> {
        &self.sessions
    }

    /// Start the core.
    pub async fn start(&self) -> Result<(), CoreError> {
        let mut running = self.running.write();
        if *running {
            return Err(CoreError::AlreadyStarted);
        }

        *running = true;

        tracing::info!(
            public_key = %self.public_key,
            address = %self.address,
            subnet = %self.subnet,
            "Yggdrasil node started"
        );

        Ok(())
    }

    /// Stop the core.
    pub async fn stop(&self) -> Result<(), CoreError> {
        let mut running = self.running.write();
        if !*running {
            return Err(CoreError::NotStarted);
        }

        *running = false;

        tracing::info!("Yggdrasil node stopped");

        Ok(())
    }

    /// Check if the core is running.
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }
}
