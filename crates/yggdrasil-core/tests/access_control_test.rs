use yggdrasil_core::handshake::perform_handshake_with_validation;
use ed25519_dalek::SigningKey;
use tokio::io::duplex;
use std::time::Duration;

#[tokio::test]
async fn test_allowed_public_keys_accept() {
    // Create two signing keys
    let signing_key1 = SigningKey::from_bytes(&[1u8; 32]);
    let signing_key2 = SigningKey::from_bytes(&[2u8; 32]);
    
    // Server's whitelist contains CLIENT's public key (key1)
    let peer1_pubkey = hex::encode(signing_key1.verifying_key().to_bytes());
    let allowed_keys = vec![peer1_pubkey];
    
    let password = b"test_password";
    let (mut client, mut server) = duplex(1024);
    
    // Spawn server with whitelist (validates incoming peer's key)
    let server_key = signing_key2.clone();
    let allowed_keys_clone = allowed_keys.clone();
    let server_handle = tokio::spawn(async move {
        // Server validates client's key
        perform_handshake_with_validation(
            &mut server,
            &server_key,
            5,
            password,
            Duration::from_secs(5),
            Some(&allowed_keys_clone),
        ).await
    });
    
    // Client doesn't validate (outbound connection)
    let client_meta = perform_handshake_with_validation(
        &mut client,
        &signing_key1,
        10,
        password,
        Duration::from_secs(5),
        None,
    ).await.unwrap();
    
    // Server should succeed since client's key is in whitelist
    let server_meta = server_handle.await.unwrap().unwrap();
    
    // Verify handshake completed
    assert_eq!(client_meta.public_key.to_bytes(), signing_key2.verifying_key().to_bytes());
    assert_eq!(server_meta.public_key.to_bytes(), signing_key1.verifying_key().to_bytes());
}

#[tokio::test]
async fn test_allowed_public_keys_reject() {
    // Create two signing keys
    let signing_key1 = SigningKey::from_bytes(&[1u8; 32]);
    let signing_key2 = SigningKey::from_bytes(&[2u8; 32]);
    let signing_key3 = SigningKey::from_bytes(&[3u8; 32]);
    
    // Whitelist only contains key3, but peer is using key2
    let peer3_pubkey = hex::encode(signing_key3.verifying_key().to_bytes());
    let allowed_keys = vec![peer3_pubkey];
    
    let password = b"test_password";
    let (mut client, mut server) = duplex(1024);
    
    // Spawn server with whitelist (validates incoming peer's key)
    let server_key = signing_key1.clone();
    let allowed_keys_clone = allowed_keys.clone();
    let server_handle = tokio::spawn(async move {
        // Server validates client's public key
        perform_handshake_with_validation(
            &mut server,
            &server_key,
            5,
            password,
            Duration::from_secs(5),
            Some(&allowed_keys_clone),
        ).await
    });
    
    // Client attempts to connect
    let client_result = perform_handshake_with_validation(
        &mut client,
        &signing_key2,
        10,
        password,
        Duration::from_secs(5),
        None,
    ).await;
    
    // Server should reject because client's key is not in whitelist
    let server_result = server_handle.await.unwrap();
    
    // Either client or server should fail
    assert!(client_result.is_err() || server_result.is_err(), 
            "Handshake should fail when public key is not in whitelist");
}

#[tokio::test]
async fn test_allowed_public_keys_empty_list_accepts_all() {
    // Create two signing keys
    let signing_key1 = SigningKey::from_bytes(&[1u8; 32]);
    let signing_key2 = SigningKey::from_bytes(&[2u8; 32]);
    
    // Empty whitelist should accept all connections
    let allowed_keys: Vec<String> = vec![];
    
    let password = b"test_password";
    let (mut client, mut server) = duplex(1024);
    
    // Spawn server with empty whitelist
    let server_key = signing_key1.clone();
    let allowed_keys_clone = allowed_keys.clone();
    let server_handle = tokio::spawn(async move {
        perform_handshake_with_validation(
            &mut server,
            &server_key,
            5,
            password,
            Duration::from_secs(5),
            Some(&allowed_keys_clone),
        ).await
    });
    
    // Client connects
    let client_meta = perform_handshake_with_validation(
        &mut client,
        &signing_key2,
        10,
        password,
        Duration::from_secs(5),
        None,
    ).await.unwrap();
    
    // Server should succeed (empty list accepts all)
    let server_meta = server_handle.await.unwrap().unwrap();
    
    // Verify handshake completed
    assert_eq!(client_meta.public_key.to_bytes(), signing_key1.verifying_key().to_bytes());
    assert_eq!(server_meta.public_key.to_bytes(), signing_key2.verifying_key().to_bytes());
}

#[tokio::test]
async fn test_allowed_public_keys_case_insensitive() {
    // Create two signing keys
    let signing_key1 = SigningKey::from_bytes(&[1u8; 32]);
    let signing_key2 = SigningKey::from_bytes(&[2u8; 32]);
    
    // Server's whitelist contains CLIENT's key (key2) in uppercase
    let peer2_pubkey = hex::encode(signing_key2.verifying_key().to_bytes()).to_uppercase();
    let allowed_keys = vec![peer2_pubkey];
    
    let password = b"test_password";
    let (mut client, mut server) = duplex(1024);
    
    // Spawn server with uppercase key in whitelist
    let server_key = signing_key1.clone();
    let allowed_keys_clone = allowed_keys.clone();
    let server_handle = tokio::spawn(async move {
        perform_handshake_with_validation(
            &mut server,
            &server_key,
            5,
            password,
            Duration::from_secs(5),
            Some(&allowed_keys_clone),
        ).await
    });
    
    // Client connects (will send key in lowercase hex)
    let client_meta = perform_handshake_with_validation(
        &mut client,
        &signing_key2,
        10,
        password,
        Duration::from_secs(5),
        None,
    ).await.unwrap();
    
    // Server should succeed (case-insensitive comparison)
    let server_meta = server_handle.await.unwrap().unwrap();
    
    // Verify handshake completed
    assert_eq!(client_meta.public_key.to_bytes(), signing_key1.verifying_key().to_bytes());
    assert_eq!(server_meta.public_key.to_bytes(), signing_key2.verifying_key().to_bytes());
}
