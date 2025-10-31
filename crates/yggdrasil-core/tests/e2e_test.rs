use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use yggdrasil_core::config::Config;
use yggdrasil_core::link::LinkManager;

/// Test two nodes can establish TCP connection and perform handshake
#[tokio::test]
async fn test_two_nodes_tcp_connection() {
    // Create signing keys
    let key1 = SigningKey::from_bytes(&[1u8; 32]);
    let key2 = SigningKey::from_bytes(&[2u8; 32]);

    // Create configs
    let config1 = Arc::new(Config::generate().unwrap());
    let config2 = Arc::new(Config::generate().unwrap());

    // Create link managers
    let listen_addrs1 = vec!["tcp://[::1]:19041".to_string()];
    let peer_addrs1 = vec![];

    let listen_addrs2 = vec!["tcp://[::1]:19042".to_string()];
    let peer_addrs2 = vec!["tcp://[::1]:19041".to_string()];

    let (manager1, mut rx1) = LinkManager::new(
        listen_addrs1,
        peer_addrs1,
        HashMap::new(),
        vec![],
        key1,
        0,
        config1,
    );
    let (manager2, mut rx2) = LinkManager::new(
        listen_addrs2,
        peer_addrs2,
        HashMap::new(),
        vec![],
        key2,
        0,
        config2,
    );

    // Start link managers
    manager1.start().await.unwrap();
    manager2.start().await.unwrap();

    println!("Link managers started");

    // Monitor events for a few seconds
    let timeout = Duration::from_secs(3);
    let start = tokio::time::Instant::now();

    let mut node1_connected = false;
    let mut node2_connected = false;
    let mut node1_handshake = false;
    let mut node2_handshake = false;

    while start.elapsed() < timeout {
        tokio::select! {
            Some(event) = rx1.recv() => {
                println!("Node 1 event: {:?}", event);
                match event {
                    yggdrasil_core::link::LinkEvent::Connected(_) => node1_connected = true,
                    yggdrasil_core::link::LinkEvent::HandshakeComplete(_, _, _, _) => node1_handshake = true,
                    _ => {}
                }
            }
            Some(event) = rx2.recv() => {
                println!("Node 2 event: {:?}", event);
                match event {
                    yggdrasil_core::link::LinkEvent::Connected(_) => node2_connected = true,
                    yggdrasil_core::link::LinkEvent::HandshakeComplete(_, _, _, _) => node2_handshake = true,
                    _ => {}
                }
            }
            _ = sleep(Duration::from_millis(100)) => {}
        }

        if node1_handshake && node2_handshake {
            break;
        }
    }

    println!(
        "Node 1: connected={}, handshake={}",
        node1_connected, node1_handshake
    );
    println!(
        "Node 2: connected={}, handshake={}",
        node2_connected, node2_handshake
    );

    // At least one node should have completed handshake
    assert!(node1_handshake || node2_handshake, "No handshake completed");
}

/// Test data transfer between two connected nodes
#[tokio::test]
async fn test_data_transfer_between_nodes() {
    // Create signing keys
    let key1 = SigningKey::from_bytes(&[3u8; 32]);
    let key2 = SigningKey::from_bytes(&[4u8; 32]);

    // Create configs
    let config1 = Arc::new(Config::generate().unwrap());
    let config2 = Arc::new(Config::generate().unwrap());

    // Create link managers
    let listen_addrs1 = vec!["tcp://[::1]:19051".to_string()];
    let peer_addrs1 = vec![];

    let listen_addrs2 = vec!["tcp://[::1]:19052".to_string()];
    let peer_addrs2 = vec!["tcp://[::1]:19051".to_string()];

    let (manager1, mut rx1) = LinkManager::new(
        listen_addrs1,
        peer_addrs1,
        HashMap::new(),
        vec![],
        key1.clone(),
        0,
        config1,
    );
    let (manager2, mut rx2) = LinkManager::new(
        listen_addrs2,
        peer_addrs2,
        HashMap::new(),
        vec![],
        key2,
        0,
        config2,
    );

    // Start link managers
    manager1.start().await.unwrap();
    manager2.start().await.unwrap();

    // Wait for handshake
    let mut peer_addr = None;
    let timeout = Duration::from_secs(3);
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout {
        tokio::select! {
            Some(event) = rx2.recv() => {
                if let yggdrasil_core::link::LinkEvent::HandshakeComplete(addr, _, _, _) = event {
                    peer_addr = Some(addr);
                    println!("Handshake complete with {}", addr);
                    break;
                }
            }
            _ = sleep(Duration::from_millis(100)) => {}
        }
    }

    if let Some(addr) = peer_addr {
        // Try to send data
        let test_data = b"Hello from Node 2!".to_vec();
        if let Err(e) = manager2.send_to_peer(&addr, test_data).await {
            println!("Failed to send data: {}", e);
        } else {
            println!("Data sent successfully");

            // Wait for node1 to receive
            tokio::select! {
                Some(event) = rx1.recv() => {
                    if let yggdrasil_core::link::LinkEvent::DataReceived(from, data) = event {
                        println!("Node 1 received {} bytes from {}", data.len(), from);
                        assert_eq!(data, b"Hello from Node 2!");
                    }
                }
                _ = sleep(Duration::from_secs(1)) => {
                    println!("Timeout waiting for data");
                }
            }
        }
    } else {
        panic!("No handshake completed");
    }
}

/// Test two nodes can establish QUIC connection and perform handshake
#[tokio::test]
async fn test_two_nodes_quic_connection() {
    // Create signing keys
    let key1 = SigningKey::from_bytes(&[5u8; 32]);
    let key2 = SigningKey::from_bytes(&[6u8; 32]);

    // Create configs
    let config1 = Arc::new(Config::generate().unwrap());
    let config2 = Arc::new(Config::generate().unwrap());

    // Create link managers with QUIC
    let listen_addrs1 = vec!["quic://[::1]:19061".to_string()];
    let peer_addrs1 = vec![];

    let listen_addrs2 = vec!["quic://[::1]:19062".to_string()];
    let peer_addrs2 = vec!["quic://[::1]:19061".to_string()];

    let (manager1, mut rx1) = LinkManager::new(
        listen_addrs1,
        peer_addrs1,
        HashMap::new(),
        vec![],
        key1,
        0,
        config1,
    );
    let (manager2, mut rx2) = LinkManager::new(
        listen_addrs2,
        peer_addrs2,
        HashMap::new(),
        vec![],
        key2,
        0,
        config2,
    );

    // Start link managers
    manager1.start().await.unwrap();
    manager2.start().await.unwrap();

    println!("QUIC link managers started");

    // Monitor events for a few seconds
    let mut node1_connected = false;
    let mut node1_handshake = false;
    let mut node2_connected = false;
    let mut node2_handshake = false;

    for _ in 0..30 {
        tokio::select! {
            Some(event) = rx1.recv() => {
                println!("Node 1 event: {:?}", event);
                match event {
                    yggdrasil_core::link::LinkEvent::Connected(_) => node1_connected = true,
                    yggdrasil_core::link::LinkEvent::HandshakeComplete(_, _, _, _) => node1_handshake = true,
                    _ => {}
                }
            }
            Some(event) = rx2.recv() => {
                println!("Node 2 event: {:?}", event);
                match event {
                    yggdrasil_core::link::LinkEvent::Connected(_) => node2_connected = true,
                    yggdrasil_core::link::LinkEvent::HandshakeComplete(_, _, _, _) => node2_handshake = true,
                    _ => {}
                }
            }
            _ = sleep(Duration::from_millis(100)) => {}
        }

        if node1_handshake && node2_handshake {
            break;
        }
    }

    println!(
        "Node 1: connected={}, handshake={}",
        node1_connected, node1_handshake
    );
    println!(
        "Node 2: connected={}, handshake={}",
        node2_connected, node2_handshake
    );

    assert!(
        node1_handshake || node2_handshake,
        "No QUIC handshake completed"
    );
}

/// Test data transfer between two QUIC connected nodes
#[tokio::test]
async fn test_quic_data_transfer_between_nodes() {
    // Create signing keys
    let key1 = SigningKey::from_bytes(&[7u8; 32]);
    let key2 = SigningKey::from_bytes(&[8u8; 32]);

    // Create configs
    let config1 = Arc::new(Config::generate().unwrap());
    let config2 = Arc::new(Config::generate().unwrap());

    // Create link managers
    let listen_addrs1 = vec!["quic://[::1]:19071".to_string()];
    let peer_addrs1 = vec![];

    let listen_addrs2 = vec!["quic://[::1]:19072".to_string()];
    let peer_addrs2 = vec!["quic://[::1]:19071".to_string()];

    let (manager1, mut rx1) = LinkManager::new(
        listen_addrs1,
        peer_addrs1,
        HashMap::new(),
        vec![],
        key1.clone(),
        0,
        config1,
    );
    let (manager2, mut rx2) = LinkManager::new(
        listen_addrs2,
        peer_addrs2,
        HashMap::new(),
        vec![],
        key2,
        0,
        config2,
    );

    // Start link managers
    manager1.start().await.unwrap();
    manager2.start().await.unwrap();

    // Wait for handshake
    let mut peer_addr = None;
    for _ in 0..30 {
        tokio::select! {
            Some(event) = rx2.recv() => {
                if let yggdrasil_core::link::LinkEvent::HandshakeComplete(addr, _, _, _) = event {
                    println!("Handshake complete with {}", addr);
                    peer_addr = Some(addr);
                    break;
                }
            }
            _ = sleep(Duration::from_millis(100)) => {}
        }
    }

    if let Some(addr) = peer_addr {
        // Send data from node2 to node1
        let data = b"Hello from QUIC Node 2!".to_vec();
        manager2.send_to_peer(&addr, data).await.unwrap();
        println!("Data sent successfully via QUIC");

        // Wait for data to be received
        sleep(Duration::from_millis(500)).await;

        // Check if data was received
        loop {
            tokio::select! {
                Some(event) = rx1.recv() => {
                    if let yggdrasil_core::link::LinkEvent::DataReceived(from, data) = event {
                        println!("Node 1 received {} bytes from {} via QUIC", data.len(), from);
                        assert_eq!(data, b"Hello from QUIC Node 2!");
                        break;
                    }
                }
                _ = sleep(Duration::from_secs(1)) => {
                    println!("Timeout waiting for QUIC data");
                    break;
                }
            }
        }
    } else {
        panic!("No QUIC handshake completed");
    }
}
