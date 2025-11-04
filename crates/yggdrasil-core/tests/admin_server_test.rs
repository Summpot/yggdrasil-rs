use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use yggdrasil_core::{AdminClient, Config, Core};

// Helper function to create admin endpoint appropriate for the platform
#[cfg(unix)]
fn create_admin_endpoint(temp_dir: &TempDir) -> (String, String) {
    let socket_path = temp_dir.path().join("admin.sock");
    let listen_addr = format!("unix://{}", socket_path.display());
    let client_addr = socket_path.to_str().unwrap().to_string();
    (listen_addr, client_addr)
}

#[cfg(not(unix))]
fn create_admin_endpoint(_temp_dir: &TempDir) -> (String, String) {
    // Use TCP on Windows with a random high port
    // Use a different port for each test to avoid conflicts when running in parallel
    use std::sync::atomic::{AtomicU16, Ordering};
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(19000);
    
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let addr = format!("127.0.0.1:{}", port);
    let listen_addr = format!("tcp://{}", addr);
    (listen_addr, addr)
}

#[tokio::test]
async fn test_admin_server_get_self() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let (listen_addr, client_addr) = create_admin_endpoint(&temp_dir);

    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(listen_addr);
    config.if_name = "none".to_string();

    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();

    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });

    // Wait for admin socket to be ready
    sleep(Duration::from_millis(100)).await;

    let client = AdminClient::new(client_addr);
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
    let (listen_addr, client_addr) = create_admin_endpoint(&temp_dir);

    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(listen_addr);
    config.if_name = "none".to_string();

    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();

    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });

    sleep(Duration::from_millis(100)).await;

    let client = AdminClient::new(client_addr);
    let response = client.get_peers().await?;

    // Initially no peers
    assert!(response.peers.is_empty());

    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_get_paths() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let (listen_addr, client_addr) = create_admin_endpoint(&temp_dir);

    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(listen_addr);
    config.if_name = "none".to_string();

    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();

    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });

    sleep(Duration::from_millis(100)).await;

    let client = AdminClient::new(client_addr);
    let response = client.get_paths().await?;

    // Initially no paths
    assert!(response.paths.is_empty());

    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_get_sessions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let (listen_addr, client_addr) = create_admin_endpoint(&temp_dir);

    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(listen_addr);
    config.if_name = "none".to_string();

    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();

    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });

    sleep(Duration::from_millis(100)).await;

    let client = AdminClient::new(client_addr);
    let response = client.get_sessions().await?;

    // Initially no sessions
    assert!(response.sessions.is_empty());

    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_add_remove_peer() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let (listen_addr, client_addr) = create_admin_endpoint(&temp_dir);

    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(listen_addr);
    config.if_name = "none".to_string();

    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();

    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });

    sleep(Duration::from_millis(100)).await;

    let client = AdminClient::new(client_addr);

    // Add a peer
    let add_response = client.add_peer("tcp://invalid.example:9001", None).await?;
    assert!(add_response.success.unwrap_or(false) || add_response.error.is_some());

    // Remove a peer
    let remove_response = client
        .remove_peer("tcp://invalid.example:9001", None)
        .await?;
    assert!(remove_response.success.unwrap_or(false) || remove_response.error.is_some());

    core.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_admin_server_list() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let (listen_addr, client_addr) = create_admin_endpoint(&temp_dir);

    let mut config = Config::generate()?;
    config.listen = vec![];
    config.peers = vec![];
    config.admin_listen = Some(listen_addr);
    config.if_name = "none".to_string();

    let core = Arc::new(Core::new(config).await?);
    let core_clone = core.clone();

    tokio::spawn(async move {
        let _ = core_clone.start().await;
    });

    sleep(Duration::from_millis(100)).await;

    let client = AdminClient::new(client_addr);
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
