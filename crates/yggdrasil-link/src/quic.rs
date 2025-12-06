//! QUIC link implementation using quinn.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::Mutex;
use yggdrasil_types::PublicKey;

use crate::link::{Link, LinkConfig, LinkError, LinkInfo};

/// A QUIC link.
pub struct QuicLink {
    info: LinkInfo,
    connection: Connection,
    send_stream: Mutex<SendStream>,
    recv_stream: Mutex<RecvStream>,
    connected: AtomicBool,
    config: LinkConfig,
}

impl QuicLink {
    /// Create a new QUIC link from an established connection.
    pub async fn new(
        connection: Connection,
        remote_key: PublicKey,
        outbound: bool,
        config: LinkConfig,
    ) -> Result<Self, LinkError> {
        let remote_addr = connection.remote_address();
        let local_addr = connection
            .local_ip()
            .map(|ip| SocketAddr::new(ip, 0))
            .unwrap_or_else(|| SocketAddr::new([0, 0, 0, 0].into(), 0));

        // Open a bidirectional stream for communication
        let (send_stream, recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| LinkError::Protocol(format!("failed to open QUIC stream: {}", e)))?;

        Ok(Self {
            info: LinkInfo {
                remote_key,
                remote_addr,
                local_addr,
                link_type: "quic".to_string(),
                outbound,
                established: Instant::now(),
            },
            connection,
            send_stream: Mutex::new(send_stream),
            recv_stream: Mutex::new(recv_stream),
            connected: AtomicBool::new(true),
            config,
        })
    }

    /// Accept an incoming QUIC connection and create a link.
    pub async fn accept(
        connection: Connection,
        remote_key: PublicKey,
        config: LinkConfig,
    ) -> Result<Self, LinkError> {
        let remote_addr = connection.remote_address();
        let local_addr = connection
            .local_ip()
            .map(|ip| SocketAddr::new(ip, 0))
            .unwrap_or_else(|| SocketAddr::new([0, 0, 0, 0].into(), 0));

        // Accept an incoming bidirectional stream
        let (send_stream, recv_stream) = connection
            .accept_bi()
            .await
            .map_err(|e| LinkError::Protocol(format!("failed to accept QUIC stream: {}", e)))?;

        Ok(Self {
            info: LinkInfo {
                remote_key,
                remote_addr,
                local_addr,
                link_type: "quic".to_string(),
                outbound: false,
                established: Instant::now(),
            },
            connection,
            send_stream: Mutex::new(send_stream),
            recv_stream: Mutex::new(recv_stream),
            connected: AtomicBool::new(true),
            config,
        })
    }

    /// Get the underlying QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

#[async_trait]
impl Link for QuicLink {
    fn info(&self) -> &LinkInfo {
        &self.info
    }

    async fn send(&self, data: &[u8]) -> Result<(), LinkError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkError::Closed);
        }

        if data.len() > self.config.max_message_size {
            return Err(LinkError::MessageTooLarge {
                size: data.len(),
                max: self.config.max_message_size,
            });
        }

        let mut stream = self.send_stream.lock().await;

        // Write length prefix (2 bytes, big endian)
        let len = data.len() as u16;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| LinkError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        stream
            .write_all(data)
            .await
            .map_err(|e| LinkError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, LinkError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkError::Closed);
        }

        let mut stream = self.recv_stream.lock().await;

        // Read length prefix
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.map_err(|e| match e {
            quinn::ReadExactError::FinishedEarly(_) => LinkError::Closed,
            quinn::ReadExactError::ReadError(e) => {
                LinkError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        })?;
        let len = u16::from_be_bytes(len_buf) as usize;

        if len > self.config.max_message_size {
            return Err(LinkError::MessageTooLarge {
                size: len,
                max: self.config.max_message_size,
            });
        }

        // Read message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.map_err(|e| match e {
            quinn::ReadExactError::FinishedEarly(_) => LinkError::Closed,
            quinn::ReadExactError::ReadError(e) => {
                LinkError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        })?;

        Ok(buf)
    }

    async fn close(&self) -> Result<(), LinkError> {
        self.connected.store(false, Ordering::Release);
        self.connection.close(0u32.into(), b"closed");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire) && self.connection.close_reason().is_none()
    }
}

/// QUIC endpoint configuration.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Server name for TLS verification.
    pub server_name: String,
    /// Whether to skip certificate verification (for self-signed certs).
    pub skip_verification: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            server_name: "yggdrasil".to_string(),
            skip_verification: true,
        }
    }
}

/// Create a QUIC endpoint for client connections.
pub fn create_client_endpoint(bind_addr: SocketAddr) -> Result<Endpoint, LinkError> {
    let mut endpoint = Endpoint::client(bind_addr)?;

    // Configure with skip verification for self-signed certs
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| LinkError::Tls(e.to_string()))?,
    ));
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Create a QUIC endpoint for server connections.
pub fn create_server_endpoint(
    bind_addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Endpoint, LinkError> {
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| LinkError::Tls(e.to_string()))?;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| LinkError::Tls(e.to_string()))?,
    ));

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

/// Skip server certificate verification (for self-signed certs).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
