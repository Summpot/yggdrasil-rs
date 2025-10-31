use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use yggdrasil_core::{Config, Core};

#[tokio::test]
#[ignore] // Run manually with: cargo test websocket_test -- --ignored
async fn test_websocket_listener() -> Result<()> {
    env_logger::init();

    // Create configuration with WebSocket listener
    let mut config = Config::generate()?;
    config.listen = vec!["ws://127.0.0.1:9001".to_string()];
    config.peers = vec![];
    config.admin_listen = Some("unix:///tmp/yggdrasil-ws-test.sock".to_string());
    config.if_name = "none".to_string();

    // Start core
    let core = Arc::new(Core::new(config).await?);
    core.clone().start().await?;

    println!("WebSocket listener started on ws://127.0.0.1:9001");
    println!("Test will run for 10 seconds...");
    println!("You can test with: websocat ws://127.0.0.1:9001");

    // Wait for 10 seconds to allow manual testing
    sleep(Duration::from_secs(10)).await;

    core.stop().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Run manually with: cargo test websocket_connection -- --ignored
async fn test_websocket_connection() -> Result<()> {
    env_logger::init();

    // Create two nodes
    let mut config1 = Config::generate()?;
    config1.listen = vec!["ws://127.0.0.1:9002".to_string()];
    config1.peers = vec![];
    config1.admin_listen = Some("unix:///tmp/yggdrasil-ws1.sock".to_string());
    config1.if_name = "none".to_string();

    let mut config2 = Config::generate()?;
    config2.listen = vec![];
    config2.peers = vec!["ws://127.0.0.1:9002".to_string()];
    config2.admin_listen = Some("unix:///tmp/yggdrasil-ws2.sock".to_string());
    config2.if_name = "none".to_string();

    // Start both cores
    let core1 = Arc::new(Core::new(config1).await?);
    core1.clone().start().await?;

    let core2 = Arc::new(Core::new(config2).await?);
    core2.clone().start().await?;

    println!("Node 1 listening on ws://127.0.0.1:9002");
    println!("Node 2 connecting to Node 1...");

    // Wait for connection to establish
    sleep(Duration::from_secs(5)).await;

    println!("Connection test completed");

    // Cleanup
    core1.stop().await?;
    core2.stop().await?;

    Ok(())
}

#[tokio::test]
#[ignore] // Run manually with: cargo test test_wss_support -- --ignored
async fn test_wss_support() -> Result<()> {
    env_logger::init();

    // Create two nodes with WSS (WebSocket Secure) support
    // The LinkManager will auto-generate self-signed certificates

    let mut config1 = Config::generate()?;
    config1.listen = vec!["wss://127.0.0.1:9443".to_string()];
    config1.peers = vec![];
    config1.admin_listen = Some("unix:///tmp/yggdrasil-wss1.sock".to_string());
    config1.if_name = "none".to_string();

    let mut config2 = Config::generate()?;
    config2.listen = vec![];
    config2.peers = vec!["wss://127.0.0.1:9443".to_string()];
    config2.admin_listen = Some("unix:///tmp/yggdrasil-wss2.sock".to_string());
    config2.if_name = "none".to_string();

    println!("Starting WSS (WebSocket Secure) test...");
    println!("Node 1 will generate a self-signed certificate for wss://127.0.0.1:9443");

    // Start node 1 with WSS listener
    let core1 = Arc::new(Core::new(config1).await?);
    core1.clone().start().await?;

    println!("Node 1 WSS listener started");

    // Give listener time to start
    sleep(Duration::from_secs(1)).await;

    // Start node 2 to connect via WSS
    let core2 = Arc::new(Core::new(config2).await?);
    core2.clone().start().await?;

    println!("Node 2 connecting to Node 1 via WSS...");

    // Wait for connection to establish
    // Note: This may fail if certificate validation is strict
    // In production, you'd use proper certificates
    sleep(Duration::from_secs(5)).await;

    println!("WSS connection test completed");
    println!("Note: Self-signed certificates are used for testing");
    println!("In production, use proper TLS certificates");

    // Cleanup
    core1.stop().await?;
    core2.stop().await?;

    Ok(())
}
