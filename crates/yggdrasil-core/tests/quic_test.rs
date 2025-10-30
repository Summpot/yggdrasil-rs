use yggdrasil_core::link::LinkManager;
use yggdrasil_core::config::Config;
use std::time::Duration;
use tokio::time::sleep;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_quic_listener_startup() {
    // Test that QUIC listener can start successfully
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let config = Arc::new(Config::generate().unwrap());
    
    let listen_addrs = vec!["quic://[::1]:0".to_string()]; // Use random port
    let peer_addrs = vec![];
    
    let (manager, _rx) = LinkManager::new(
        listen_addrs, 
        peer_addrs, 
        HashMap::new(), 
        vec![], 
        key, 
        0, 
        config
    );
    
    // Start link manager (which should start QUIC listener)
    manager.start().await.unwrap();
    
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    println!("QUIC listener startup test completed");
}

#[tokio::test]
async fn test_quic_connection_pair() {
    // Test QUIC connection between two nodes
    
    let key1 = SigningKey::from_bytes(&[1u8; 32]);
    let key2 = SigningKey::from_bytes(&[2u8; 32]);
    
    let config1 = Arc::new(Config::generate().unwrap());
    let config2 = Arc::new(Config::generate().unwrap());
    
    // Node 1 - listener
    let listen_addrs1 = vec!["quic://[::1]:19001".to_string()];
    let peer_addrs1 = vec![];
    
    let (manager1, mut rx1) = LinkManager::new(
        listen_addrs1,
        peer_addrs1,
        HashMap::new(),
        vec![],
        key1,
        0,
        config1,
    );
    
    // Node 2 - connector
    let listen_addrs2 = vec![];
    let peer_addrs2 = vec!["quic://[::1]:19001".to_string()];
    
    let (manager2, mut rx2) = LinkManager::new(
        listen_addrs2,
        peer_addrs2,
        HashMap::new(),
        vec![],
        key2,
        0,
        config2,
    );
    
    // Start both managers
    manager1.start().await.unwrap();
    manager2.start().await.unwrap();
    
    println!("QUIC managers started");
    
    // Monitor events for a few seconds
    let timeout = Duration::from_secs(5);
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
    
    println!("Node 1: connected={}, handshake={}", node1_connected, node1_handshake);
    println!("Node 2: connected={}, handshake={}", node2_connected, node2_handshake);
    
    // At least one node should have completed handshake
    assert!(node1_handshake || node2_handshake, "No QUIC handshake completed");
    
    println!("QUIC connection pair test completed");
}

#[tokio::test]
async fn test_quic_three_node_chain() {
    // Test QUIC with three nodes in a chain: Node1 <-> Node2 <-> Node3
    
    let key1 = SigningKey::from_bytes(&[1u8; 32]);
    let key2 = SigningKey::from_bytes(&[2u8; 32]);
    let key3 = SigningKey::from_bytes(&[3u8; 32]);
    
    let config1 = Arc::new(Config::generate().unwrap());
    let config2 = Arc::new(Config::generate().unwrap());
    let config3 = Arc::new(Config::generate().unwrap());
    
    // Node 1 - listener
    let (manager1, mut rx1) = LinkManager::new(
        vec!["quic://[::1]:19011".to_string()],
        vec![],
        HashMap::new(),
        vec![],
        key1,
        0,
        config1,
    );
    
    // Node 2 - middle (connects to node1 and listens for node3)
    let (manager2, mut rx2) = LinkManager::new(
        vec!["quic://[::1]:19012".to_string()],
        vec!["quic://[::1]:19011".to_string()],
        HashMap::new(),
        vec![],
        key2,
        0,
        config2,
    );
    
    // Node 3 - connects to node2
    let (manager3, mut rx3) = LinkManager::new(
        vec![],
        vec!["quic://[::1]:19012".to_string()],
        HashMap::new(),
        vec![],
        key3,
        0,
        config3,
    );
    
    // Start all managers
    manager1.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    manager2.start().await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    manager3.start().await.unwrap();
    
    println!("All QUIC managers started");
    
    // Monitor events
    let timeout = Duration::from_secs(7);
    let start = tokio::time::Instant::now();
    
    let mut handshakes = 0;
    
    while start.elapsed() < timeout {
        tokio::select! {
            Some(event) = rx1.recv() => {
                println!("Node 1 event: {:?}", event);
                if matches!(event, yggdrasil_core::link::LinkEvent::HandshakeComplete(_, _, _, _)) {
                    handshakes += 1;
                }
            }
            Some(event) = rx2.recv() => {
                println!("Node 2 event: {:?}", event);
                if matches!(event, yggdrasil_core::link::LinkEvent::HandshakeComplete(_, _, _, _)) {
                    handshakes += 1;
                }
            }
            Some(event) = rx3.recv() => {
                println!("Node 3 event: {:?}", event);
                if matches!(event, yggdrasil_core::link::LinkEvent::HandshakeComplete(_, _, _, _)) {
                    handshakes += 1;
                }
            }
            _ = sleep(Duration::from_millis(100)) => {}
        }
        
        if handshakes >= 2 {
            break;
        }
    }
    
    println!("Total handshakes completed: {}", handshakes);
    assert!(handshakes >= 1, "At least one QUIC handshake should complete");
    
    println!("QUIC three-node chain test completed");
}
