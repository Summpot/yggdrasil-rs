//! TLS link implementation using tokio-rustls.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::TlsConnector;
use yggdrasil_types::PublicKey;

use crate::link::{Link, LinkConfig, LinkError, LinkInfo};

/// A TLS-wrapped TCP link (client side).
pub struct TlsClientLink {
    info: LinkInfo,
    stream: Mutex<ClientTlsStream<TcpStream>>,
    connected: AtomicBool,
    config: LinkConfig,
}

impl TlsClientLink {
    /// Create a new TLS client link from an established connection.
    pub fn new(
        stream: ClientTlsStream<TcpStream>,
        remote_key: PublicKey,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        config: LinkConfig,
    ) -> Self {
        Self {
            info: LinkInfo {
                remote_key,
                remote_addr,
                local_addr,
                link_type: "tls".to_string(),
                outbound: true,
                established: Instant::now(),
            },
            stream: Mutex::new(stream),
            connected: AtomicBool::new(true),
            config,
        }
    }

    /// Connect to a remote address with TLS.
    pub async fn connect(
        addr: SocketAddr,
        remote_key: PublicKey,
        config: LinkConfig,
        tls_config: Arc<rustls::ClientConfig>,
        server_name: &str,
    ) -> Result<Self, LinkError> {
        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| LinkError::Timeout)?
            .map_err(LinkError::Io)?;

        let local_addr = stream.local_addr()?;
        let remote_addr = stream.peer_addr()?;

        let connector = TlsConnector::from(tls_config);
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|_| LinkError::Tls("invalid server name".to_string()))?;

        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| LinkError::Tls(e.to_string()))?;

        Ok(Self::new(
            tls_stream,
            remote_key,
            remote_addr,
            local_addr,
            config,
        ))
    }
}

#[async_trait]
impl Link for TlsClientLink {
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

        let mut stream = self.stream.lock().await;

        // Write length prefix (2 bytes, big endian)
        let len = data.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, LinkError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkError::Closed);
        }

        let mut stream = self.stream.lock().await;

        // Read length prefix
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;

        if len > self.config.max_message_size {
            return Err(LinkError::MessageTooLarge {
                size: len,
                max: self.config.max_message_size,
            });
        }

        // Read message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        Ok(buf)
    }

    async fn close(&self) -> Result<(), LinkError> {
        self.connected.store(false, Ordering::Release);
        let mut stream = self.stream.lock().await;
        stream.shutdown().await?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}

/// A TLS-wrapped TCP link (server side).
pub struct TlsServerLink {
    info: LinkInfo,
    stream: Mutex<ServerTlsStream<TcpStream>>,
    connected: AtomicBool,
    config: LinkConfig,
}

impl TlsServerLink {
    /// Create a new TLS server link from an established connection.
    pub fn new(
        stream: ServerTlsStream<TcpStream>,
        remote_key: PublicKey,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        config: LinkConfig,
    ) -> Self {
        Self {
            info: LinkInfo {
                remote_key,
                remote_addr,
                local_addr,
                link_type: "tls".to_string(),
                outbound: false,
                established: Instant::now(),
            },
            stream: Mutex::new(stream),
            connected: AtomicBool::new(true),
            config,
        }
    }
}

#[async_trait]
impl Link for TlsServerLink {
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

        let mut stream = self.stream.lock().await;

        // Write length prefix (2 bytes, big endian)
        let len = data.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, LinkError> {
        if !self.connected.load(Ordering::Acquire) {
            return Err(LinkError::Closed);
        }

        let mut stream = self.stream.lock().await;

        // Read length prefix
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;

        if len > self.config.max_message_size {
            return Err(LinkError::MessageTooLarge {
                size: len,
                max: self.config.max_message_size,
            });
        }

        // Read message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        Ok(buf)
    }

    async fn close(&self) -> Result<(), LinkError> {
        self.connected.store(false, Ordering::Release);
        let mut stream = self.stream.lock().await;
        stream.shutdown().await?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}

/// Create a default TLS client configuration that skips certificate verification.
/// This is used for self-signed certificates in Yggdrasil.
/// Supports SSLKEYLOGFILE environment variable for Wireshark decryption via rustls.
pub fn create_insecure_client_config() -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerVerifier))
        .with_no_client_auth();

    // Enable key logging via rustls' built-in SSLKEYLOGFILE support
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    Arc::new(config)
}

/// Create a TLS server configuration with the given certificate and key.
/// Supports SSLKEYLOGFILE environment variable for Wireshark decryption via rustls.
pub fn create_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, LinkError> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| LinkError::Tls(e.to_string()))?;

    // Enable key logging via rustls' built-in SSLKEYLOGFILE support
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(Arc::new(config))
}

/// Server certificate verifier that accepts any certificate.
#[derive(Debug)]
struct InsecureServerVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
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
