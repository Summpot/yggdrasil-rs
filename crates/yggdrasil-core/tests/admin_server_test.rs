use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use yggdrasil_core::{Config, Core, AdminClient};
use anyhow::Result;

#[tokio::test]
async fn test_admin_server_get_self() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let socket_path = temp_dir.path().join("admin.sock");
    
    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(format!("unix://{}", socket_path.display()));
    config.if_name = "none".to_string();
    
    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();
    
    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });
    
    // Wait for admin socket to be ready
    sleep(Duration::from_millis(100)).await;
    
    let client = AdminClient::new(socket_path.to_str().unwrap());
    let response = client.get_self().await?;
    
    assert!(!response.build_name.is_empty());
    assert!(!response.public_key.is_empty());
    assert!(!response.ip_address.is_empty());
    assert!(!response.subnet.is_empty());
    
    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_get_peers() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let socket_path = temp_dir.path().join("admin.sock");
    
    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(format!("unix://{}", socket_path.display()));
    config.if_name = "none".to_string();
    
    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();
    
    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });
    
    sleep(Duration::from_millis(100)).await;
    
    let client = AdminClient::new(socket_path.to_str().unwrap());
    let response = client.get_peers().await?;
    
    // Initially no peers
    assert!(response.peers.is_empty());
    
    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_get_paths() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let socket_path = temp_dir.path().join("admin.sock");
    
    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(format!("unix://{}", socket_path.display()));
    config.if_name = "none".to_string();
    
    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();
    
    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });
    
    sleep(Duration::from_millis(100)).await;
    
    let client = AdminClient::new(socket_path.to_str().unwrap());
    let response = client.get_paths().await?;
    
    // Initially no paths
    assert!(response.paths.is_empty());
    
    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_get_sessions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let socket_path = temp_dir.path().join("admin.sock");
    
    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(format!("unix://{}", socket_path.display()));
    config.if_name = "none".to_string();
    
    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();
    
    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });
    
    sleep(Duration::from_millis(100)).await;
    
    let client = AdminClient::new(socket_path.to_str().unwrap());
    let response = client.get_sessions().await?;
    
    // Initially no sessions
    assert!(response.sessions.is_empty());
    
    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_add_remove_peer() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let socket_path = temp_dir.path().join("admin.sock");
    
    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(format!("unix://{}", socket_path.display()));
    config.if_name = "none".to_string();
    
    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();
    
    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });
    
    sleep(Duration::from_millis(100)).await;
    
    let client = AdminClient::new(socket_path.to_str().unwrap());
    
    // Add a peer
    let add_response = client.add_peer("tcp://invalid.example:9001", None).await?;
    assert!(add_response.success.unwrap_or(false) || add_response.error.is_some());
    
    // Remove a peer
    let remove_response = client.remove_peer("tcp://invalid.example:9001", None).await?;
    assert!(remove_response.success.unwrap_or(false) || remove_response.error.is_some());
    
    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_list() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let socket_path = temp_dir.path().join("admin.sock");
    
    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(format!("unix://{}", socket_path.display()));
    config.if_name = "none".to_string();
    
    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();
    
    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });
    
    sleep(Duration::from_millis(100)).await;
    
    let client = AdminClient::new(socket_path.to_str().unwrap());
    let response = client.list().await?;
    
    assert!(!response.list.is_empty());
    
    // Check for required commands
    let commands: Vec<&str> = response.list.iter().map(|e| e.command.as_str()).collect();
    assert!(commands.contains(&"getSelf"));
    assert!(commands.contains(&"getPeers"));
    assert!(commands.contains(&"getPaths"));
    assert!(commands.contains(&"getSessions"));
    assert!(commands.contains(&"addPeer"));
    assert!(commands.contains(&"removePeer"));
    assert!(commands.contains(&"list"));
    
    core.stop().await?;
    Ok(())
}
