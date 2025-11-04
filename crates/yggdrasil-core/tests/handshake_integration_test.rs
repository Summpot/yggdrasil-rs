use ed25519_dalek::SigningKey;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use yggdrasil_core::handshake;

#[tokio::test]
async fn test_tcp_handshake_integration() {
    // Start a TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Create signing keys for server and client
    let server_key = SigningKey::from_bytes(&[1u8; 32]);
    let client_key = SigningKey::from_bytes(&[2u8; 32]);
    let password = b"test_password";

    // Spawn server task
    let server_key_clone = server_key.clone();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        handshake::perform_handshake(
            &mut stream,
            &server_key_clone,
            10,
            password,
            Duration::from_secs(5),
        )
        .await
    });

    // Give server time to start listening
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client
    let mut client_stream = TcpStream::connect(addr).await.unwrap();
    let client_meta = handshake::perform_handshake(
        &mut client_stream,
        &client_key,
        5,
        password,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    // Wait for server handshake
    let server_meta = server_handle.await.unwrap().unwrap();

    // Verify both sides received correct information
    assert_eq!(
        client_meta.public_key.to_bytes(),
        server_key.verifying_key().to_bytes()
    );
    assert_eq!(client_meta.priority, 10);

    assert_eq!(
        server_meta.public_key.to_bytes(),
        client_key.verifying_key().to_bytes()
    );
    assert_eq!(server_meta.priority, 5);

    // Both should be compatible
    assert!(client_meta.is_compatible());
    assert!(server_meta.is_compatible());
}

#[tokio::test]
async fn test_handshake_with_wrong_password() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_key = SigningKey::from_bytes(&[1u8; 32]);
    let client_key = SigningKey::from_bytes(&[2u8; 32]);

    // Server uses one password
    let server_password = b"correct_password";
    let server_key_clone = server_key.clone();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        handshake::perform_handshake(
            &mut stream,
            &server_key_clone,
            10,
            server_password,
            Duration::from_secs(5),
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client uses different password
    let mut client_stream = TcpStream::connect(addr).await.unwrap();
    let client_result = handshake::perform_handshake(
        &mut client_stream,
        &client_key,
        5,
        b"wrong_password",
        Duration::from_secs(5),
    )
    .await;

    // Handshake should fail
    assert!(client_result.is_err());

    // Server should also fail
    let server_result = server_handle.await.unwrap();
    assert!(server_result.is_err());
}

#[tokio::test]
async fn test_handshake_timeout() {
    use tokio::io::duplex;

    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let password = b"test";

    // Create a stream but don't send anything
    let (mut client, _server) = duplex(1024);

    // Handshake should timeout
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        handshake::perform_handshake(
            &mut client,
            &signing_key,
            0,
            password,
            Duration::from_millis(100),
        ),
    )
    .await;

    // Should timeout or return error
    assert!(result.is_err() || result.unwrap().is_err());
}
