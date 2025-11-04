use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use pem::Pem;
use rcgen::{Certificate as RcgenCertificate, CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Arc;

/// Yggdrasil network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Private key (Ed25519) - 32 bytes seed (serialized as 64 bytes hex for Go compatibility)
    #[serde(
        rename = "PrivateKey",
        skip_serializing_if = "Option::is_none",
        default,
        with = "private_key_serde"
    )]
    pub private_key: Option<[u8; 32]>,

    /// Path to private key file in PEM format (alternative to PrivateKey field)
    #[serde(
        rename = "PrivateKeyPath",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub private_key_path: Option<String>,

    /// TLS certificate (generated at runtime, not serialized)
    #[serde(skip)]
    pub certificate: Option<RcgenCertificate>,

    /// TLS certificate key pair (generated at runtime, not serialized)
    #[serde(skip)]
    pub certificate_key_pair: Option<Arc<KeyPair>>,

    /// List of outbound peer connection strings
    #[serde(rename = "Peers", default)]
    pub peers: Vec<String>,

    /// Peer connections arranged by source interface
    #[serde(
        rename = "InterfacePeers",
        default,
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    pub interface_peers: std::collections::HashMap<String, Vec<String>>,

    /// Listen addresses for incoming connections
    #[serde(rename = "Listen", default)]
    pub listen: Vec<String>,

    /// Admin socket listen address
    #[serde(
        rename = "AdminListen",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub admin_listen: Option<String>,

    /// Multicast interface configurations
    #[serde(rename = "MulticastInterfaces", default)]
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,

    /// Allowed peer public keys (access control)
    #[serde(
        rename = "AllowedPublicKeys",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_public_keys: Vec<String>,

    /// TUN interface name ("auto" for automatic, "none" to disable)
    #[serde(rename = "IfName", default = "default_if_name")]
    pub if_name: String,

    /// Maximum Transmission Unit for TUN interface
    #[serde(rename = "IfMTU", default = "default_if_mtu")]
    pub if_mtu: u64,

    /// Enable nodeinfo privacy (hide platform/version info)
    #[serde(rename = "NodeInfoPrivacy", default)]
    pub nodeinfo_privacy: bool,

    /// Optional nodeinfo key-value pairs
    #[serde(rename = "NodeInfo", default, skip_serializing_if = "Option::is_none")]
    pub nodeinfo: Option<serde_json::Value>,
}

/// Configuration for multicast interface discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastInterfaceConfig {
    /// Regular expression matched against interface name
    #[serde(rename = "Regex")]
    pub regex: String,

    /// Whether to advertise presence to other nodes
    #[serde(rename = "Beacon", default = "default_true")]
    pub beacon: bool,

    /// Whether to listen for other advertising nodes
    #[serde(rename = "Listen", default = "default_true")]
    pub listen: bool,

    /// Multicast port (optional)
    #[serde(rename = "Port", skip_serializing_if = "Option::is_none", default)]
    pub port: Option<u16>,

    /// Priority (optional)
    #[serde(rename = "Priority", skip_serializing_if = "Option::is_none", default)]
    pub priority: Option<u64>,

    /// Password for multicast authentication (optional)
    #[serde(rename = "Password", default)]
    pub password: String,
}

// Legacy structures for backward compatibility (deprecated, not exported)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct AdminConfig {
    pub endpoint: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct MulticastConfig {
    pub enabled: bool,
    pub interfaces: Vec<String>,
    pub interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct TunConfig {
    pub name: String,
    pub mtu: u32,
    pub enabled: bool,
}

// Default value functions
fn default_true() -> bool {
    true
}

fn default_if_name() -> String {
    "auto".to_string()
}

fn default_if_mtu() -> u64 {
    65535
}

fn default_multicast_interfaces() -> Vec<MulticastInterfaceConfig> {
    vec![MulticastInterfaceConfig {
        regex: ".*".to_string(),
        beacon: true,
        listen: true,
        port: None,
        priority: None,
        password: String::new(),
    }]
}

// Platform-specific default admin listen address
// Matches yggdrasil-go behavior: Unix systems use Unix sockets, Windows uses TCP
#[cfg(unix)]
fn default_admin_listen() -> String {
    "unix:///var/run/yggdrasil/yggdrasil.sock".to_string()
}

#[cfg(not(unix))]
fn default_admin_listen() -> String {
    "tcp://localhost:9001".to_string()
}

impl Config {
    /// Generate new configuration with random keys
    pub fn generate() -> Result<Self> {
        // Generate Ed25519 key pair
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());

        // Store 32-byte seed (will be serialized as 64 bytes for Go compatibility)
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&signing_key.to_bytes());

        let mut config = Config {
            private_key: Some(private_key_bytes),
            private_key_path: None,
            certificate: None,
            certificate_key_pair: None,
            peers: vec![],
            interface_peers: std::collections::HashMap::new(),
            listen: vec![],
            admin_listen: Some(default_admin_listen()),
            multicast_interfaces: default_multicast_interfaces(),
            allowed_public_keys: vec![],
            if_name: default_if_name(),
            if_mtu: default_if_mtu(),
            nodeinfo_privacy: false,
            nodeinfo: None,
        };

        // Generate self-signed certificate
        config.generate_self_signed_certificate()?;

        Ok(config)
    }

    /// Load configuration from file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read configuration file")?;

        let mut config = Self::parse_from_str(&content)?;
        config.postprocess()?;
        Ok(config)
    }

    /// Parse configuration from string
    pub fn parse_from_str(content: &str) -> Result<Self> {
        // Try parsing as HJSON (most lenient, try first)
        if let Ok(config) = serde_hjson::from_str(content) {
            return Ok(config);
        }

        // Try JSON
        if let Ok(config) = serde_json::from_str(content) {
            return Ok(config);
        }

        // Try TOML
        toml::from_str(content)
            .context("Failed to parse configuration file (tried HJSON, JSON, and TOML)")
    }

    /// Convert to HJSON string with comments (like Go implementation)
    pub fn to_hjson_with_comments(&self) -> Result<String> {
        let mut output = String::from("{\n");

        // PrivateKey
        output.push_str("  # Your private key. DO NOT share this with anyone!\n");
        if let Some(ref key_bytes) = self.private_key {
            // Generate 64-byte format (seed + public key) for Go compatibility
            let signing_key = SigningKey::from_bytes(key_bytes);
            let public_key = signing_key.verifying_key();
            let mut full_key = [0u8; 64];
            full_key[..32].copy_from_slice(key_bytes);
            full_key[32..].copy_from_slice(&public_key.to_bytes());
            output.push_str(&format!("  PrivateKey: {}\n", ::hex::encode(full_key)));
        } else {
            output.push_str("  # PrivateKey: <generate with genkeys or -genconf>\n");
        }
        output.push('\n');

        // Peers
        output.push_str("  # List of outbound peer connection strings (e.g. tls://a.b.c.d:e or\n");
        output.push_str(
            "  # socks://a.b.c.d:e/f.g.h.i:j). Connection strings can contain options.\n",
        );
        output.push_str("  # Yggdrasil has no concept of bootstrap nodes - all network traffic\n");
        output
            .push_str("  # will transit peer connections. Therefore make sure to only peer with\n");
        output.push_str("  # nearby nodes that have good connectivity and low latency.\n");
        output.push_str("  Peers: [\n");
        for peer in &self.peers {
            output.push_str(&format!("    {}\n", serde_json::to_string(peer)?));
        }
        output.push_str("  ]\n\n");

        // InterfacePeers
        output.push_str(
            "  # List of connection strings for outbound peer connections in URI format,\n",
        );
        output.push_str(
            "  # arranged by source interface, e.g. { \"eth0\": [ \"tls://a.b.c.d:e\" ] }.\n",
        );
        output.push_str(
            "  # You should only use this option if your machine is multi-homed and you\n",
        );
        output
            .push_str("  # want to establish outbound peer connections on different interfaces.\n");
        output.push_str("  InterfacePeers: ");
        if self.interface_peers.is_empty() {
            output.push_str("{}\n\n");
        } else {
            output.push_str(&serde_json::to_string_pretty(&self.interface_peers)?);
            output.push_str("\n\n");
        }

        // Listen
        output.push_str("  # Listen addresses for incoming connections. You will need to add\n");
        output
            .push_str("  # listeners in order to accept incoming peerings from non-local nodes.\n");
        output.push_str("  # Multicast peer discovery will work regardless of any listeners set\n");
        output
            .push_str("  # here. Each listener should be specified in URI format as above, e.g.\n");
        output.push_str("  # tls://0.0.0.0:0 or tls://[::]:0 to listen on all interfaces.\n");
        output.push_str("  Listen: [\n");
        for listen_addr in &self.listen {
            output.push_str(&format!("    {}\n", serde_json::to_string(listen_addr)?));
        }
        output.push_str("  ]\n\n");

        // AdminListen
        output
            .push_str("  # Listen address for admin connections. Default is to listen for local\n");
        output.push_str("  # connections either on TCP/9001 or a UNIX socket depending on your\n");
        output.push_str("  # platform. Use this value for yggdrasilctl -endpoint=X. To disable\n");
        output.push_str("  # the admin socket, use the value \"none\" instead.\n");
        let default_admin = default_admin_listen();
        let admin_listen_value = self.admin_listen.as_ref().unwrap_or(&default_admin);
        output.push_str(&format!(
            "  AdminListen: {}\n\n",
            serde_json::to_string(admin_listen_value)?
        ));

        // MulticastInterfaces
        output.push_str(
            "  # Configuration for which interfaces multicast peer discovery should be\n",
        );
        output.push_str(
            "  # enabled on. Regex is a regular expression which is matched against an\n",
        );
        output
            .push_str("  # interface name, and interfaces use the first configuration that they\n");
        output.push_str(
            "  # match against. Beacon controls whether or not your node advertises its\n",
        );
        output
            .push_str("  # presence to others, whereas Listen controls whether or not your node\n");
        output.push_str("  # listens out for and tries to connect to other advertising nodes.\n");
        output.push_str("  MulticastInterfaces: [\n");
        for iface in &self.multicast_interfaces {
            output.push_str("    {\n");
            output.push_str(&format!(
                "      Regex: {}\n",
                serde_json::to_string(&iface.regex)?
            ));
            output.push_str(&format!("      Beacon: {}\n", iface.beacon));
            output.push_str(&format!("      Listen: {}\n", iface.listen));
            if let Some(port) = iface.port {
                output.push_str(&format!("      Port: {}\n", port));
            }
            if let Some(priority) = iface.priority {
                output.push_str(&format!("      Priority: {}\n", priority));
            }
            if !iface.password.is_empty() {
                output.push_str(&format!(
                    "      Password: {}\n",
                    serde_json::to_string(&iface.password)?
                ));
            }
            output.push_str("    }\n");
        }
        output.push_str("  ]\n\n");

        // AllowedPublicKeys
        output.push_str("  # List of peer public keys to allow incoming peering connections\n");
        output.push_str("  # from. If left empty/undefined then all connections will be allowed\n");
        output.push_str("  # by default. This does not affect outgoing peerings, nor does it\n");
        output.push_str("  # affect link-local peers discovered via multicast.\n");
        output.push_str("  # WARNING: THIS IS NOT A FIREWALL and DOES NOT limit who can reach\n");
        output.push_str("  # open ports or services running on your machine!\n");
        output.push_str("  AllowedPublicKeys: [\n");
        for key in &self.allowed_public_keys {
            output.push_str(&format!("    {}\n", serde_json::to_string(key)?));
        }
        output.push_str("  ]\n\n");

        // IfName
        output
            .push_str("  # Local network interface name for TUN adapter, or \"auto\" to select\n");
        output.push_str("  # an interface automatically, or \"none\" to run without TUN.\n");
        output.push_str(&format!(
            "  IfName: {}\n\n",
            serde_json::to_string(&self.if_name)?
        ));

        // IfMTU
        output.push_str("  # Maximum Transmission Unit (MTU) size for your local TUN interface.\n");
        output
            .push_str("  # Default is the largest supported size for your platform. The lowest\n");
        output.push_str("  # possible value is 1280.\n");
        output.push_str(&format!("  IfMTU: {}\n\n", self.if_mtu));

        // NodeInfoPrivacy
        output
            .push_str("  # By default, nodeinfo contains some defaults including the platform,\n");
        output.push_str("  # architecture and Yggdrasil version. These can help when surveying\n");
        output.push_str("  # the network and diagnosing network routing problems. Enabling\n");
        output.push_str("  # nodeinfo privacy prevents this, so that only items specified in\n");
        output.push_str("  # \"NodeInfo\" are sent back if specified.\n");
        output.push_str(&format!("  NodeInfoPrivacy: {}\n\n", self.nodeinfo_privacy));

        // NodeInfo
        output.push_str("  # Optional nodeinfo. This must be a { \"key\": \"value\", ... } map\n");
        output.push_str("  # or set as null. This is entirely optional but, if set, is visible\n");
        output.push_str("  # to the whole network on request.\n");
        if let Some(ref nodeinfo) = self.nodeinfo {
            output.push_str(&format!(
                "  NodeInfo: {}\n",
                serde_json::to_string_pretty(nodeinfo)?
            ));
        } else {
            output.push_str("  NodeInfo: null\n");
        }

        output.push_str("}\n");
        Ok(output)
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &str, format: ConfigFormat) -> Result<()> {
        let content = match format {
            ConfigFormat::Hjson => self.to_hjson_with_comments()?,
            ConfigFormat::Json => serde_json::to_string_pretty(self)?,
            ConfigFormat::Toml => toml::to_string_pretty(self)?,
        };

        fs::write(path, content).context("Failed to write configuration file")
    }

    /// Get signing key from private key
    pub fn get_signing_key(&self) -> Result<SigningKey> {
        let private_key_bytes = self
            .private_key
            .ok_or_else(|| anyhow::anyhow!("No private key in configuration"))?;
        Ok(SigningKey::from_bytes(&private_key_bytes))
    }

    /// Get verifying key (public key) from private key
    pub fn get_verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        let signing_key = self.get_signing_key()?;
        Ok(signing_key.verifying_key())
    }

    /// Get address corresponding to public key
    pub fn get_address(&self) -> Result<crate::address::Address> {
        let verifying_key = self.get_verifying_key()?;
        Ok(crate::address::Address::from_public_key(&verifying_key))
    }

    /// Get subnet corresponding to public key
    pub fn get_subnet(&self) -> Result<crate::address::Subnet> {
        let verifying_key = self.get_verifying_key()?;
        Ok(crate::address::Subnet::from_public_key(&verifying_key))
    }

    /// Generate self-signed TLS certificate from current private key
    ///
    /// Creates a self-signed certificate with:
    /// - CommonName set to hex-encoded public key
    /// - Validity from now until year 9999 (effectively never expires)
    /// - Key usage for key encipherment and digital signature
    /// - Extended key usage for server authentication
    pub fn generate_self_signed_certificate(&mut self) -> Result<()> {
        let signing_key = self.get_signing_key()?;
        let public_key = signing_key.verifying_key();

        // Create certificate parameters
        let mut params = CertificateParams::default();

        // Set subject (CommonName = public key hex)
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(
            rcgen::DnType::CommonName,
            hex::encode(public_key.as_bytes()),
        );
        params.distinguished_name = distinguished_name;

        // Set validity period (until year 9999 - effectively never expires, matching Go implementation)
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::new_utc(
            time::Date::from_calendar_date(9999, time::Month::December, 31)
                .map_err(|e| anyhow::anyhow!("Failed to create expiry date: {}", e))?,
            time::Time::from_hms(23, 59, 59)
                .map_err(|e| anyhow::anyhow!("Failed to create expiry time: {}", e))?,
        );

        // Set key usage
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        // Set extended key usage for server auth
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        // Generate certificate with default key pair
        // Note: The certificate's key pair is separate from the node's Ed25519 identity key.
        // What matters for Yggdrasil is the CommonName (public key hex), not the cert's key type.
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        self.certificate = Some(cert);
        self.certificate_key_pair = Some(Arc::new(key_pair));

        Ok(())
    }

    /// Load private key from PEM file
    ///
    /// Supports PEM-encoded Ed25519 private keys.
    /// Updates both the private_key field and regenerates the certificate.
    pub fn load_pem_private_key(&mut self, path: &str) -> Result<()> {
        let pem_data = fs::read_to_string(path)
            .context(format!("Failed to read private key file: {}", path))?;

        let pem = pem::parse(&pem_data).context("Failed to parse PEM data")?;

        if pem.tag() != "PRIVATE KEY" {
            return Err(anyhow::anyhow!(
                "Expected PEM tag 'PRIVATE KEY', got '{}'",
                pem.tag()
            ));
        }

        // For Ed25519, the DER content should be 32 or 48 bytes
        // Extract the 32-byte seed
        let contents = pem.contents();
        let seed = if contents.len() == 32 {
            contents
        } else if contents.len() >= 32 {
            // PKCS#8 format may have additional wrapper bytes
            // Try to extract last 32 bytes as seed
            &contents[contents.len() - 32..]
        } else {
            return Err(anyhow::anyhow!(
                "Invalid private key length: {}",
                contents.len()
            ));
        };

        // Create signing key from seed
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);
        let signing_key = SigningKey::from_bytes(&seed_array);

        self.private_key = Some(signing_key.to_bytes());

        // Regenerate certificate with new key
        self.generate_self_signed_certificate()?;

        Ok(())
    }

    /// Save private key to PEM file
    ///
    /// Saves the current private key to a file in PEM format.
    pub fn save_pem_private_key(&self, path: &str) -> Result<()> {
        let signing_key = self.get_signing_key()?;
        let seed_bytes = signing_key.to_bytes();

        // Create PEM with raw seed bytes
        let pem = Pem::new("PRIVATE KEY", seed_bytes.to_vec());
        let pem_str = pem::encode(&pem);

        fs::write(path, pem_str).context(format!("Failed to write private key file: {}", path))?;

        Ok(())
    }

    /// Get certificate in PEM format
    ///
    /// Returns the self-signed certificate as a PEM-encoded string.
    /// Certificate must be generated first via generate_self_signed_certificate().
    pub fn get_certificate_pem(&self) -> Result<String> {
        let cert = self.certificate.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "No certificate available. Call generate_self_signed_certificate() first."
            )
        })?;

        Ok(cert.pem())
    }

    /// Process configuration after loading
    ///
    /// If PrivateKeyPath is set, loads the private key from file.
    /// Then ensures a certificate is generated.
    pub fn postprocess(&mut self) -> Result<()> {
        // Load private key from path if specified
        if let Some(ref path) = self.private_key_path.clone() {
            self.load_pem_private_key(path)?;
        }

        // Ensure certificate is generated
        if self.certificate.is_none() && self.private_key.is_some() {
            self.generate_self_signed_certificate()?;
        }

        Ok(())
    }
}

/// Configuration file format
#[derive(Debug, Clone, Copy)]
pub enum ConfigFormat {
    Json,
    Hjson,
    Toml,
}

/// Custom serialization for private key to match Go format (64 bytes hex)
mod private_key_serde {
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize as 64-byte hex string (seed + public key) for Go compatibility
    pub fn serialize<S>(key: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match key {
            Some(seed) => {
                // Create signing key from seed and get public key
                let signing_key = SigningKey::from_bytes(seed);
                let public_key = signing_key.verifying_key();

                // Construct 64-byte array (seed + public)
                let mut full_key = [0u8; 64];
                full_key[..32].copy_from_slice(seed);
                full_key[32..].copy_from_slice(&public_key.to_bytes());

                serializer.serialize_str(&::hex::encode(full_key))
            }
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize from hex string (supports both 32 and 64 byte keys)
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_s: Option<String> = Option::deserialize(deserializer)?;
        match opt_s {
            Some(s) => {
                let bytes = ::hex::decode(&s).map_err(serde::de::Error::custom)?;
                match bytes.len() {
                    32 => {
                        // 32-byte key (just seed)
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&bytes);
                        Ok(Some(seed))
                    }
                    64 => {
                        // 64-byte key (seed + public), take first 32 bytes
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&bytes[..32]);
                        Ok(Some(seed))
                    }
                    _ => Err(serde::de::Error::custom(format!(
                        "Invalid private key length: expected 32 or 64 bytes, got {}",
                        bytes.len()
                    ))),
                }
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_config() {
        let config = Config::generate().unwrap();
        assert!(config.private_key.is_some());
        assert_eq!(config.peers.len(), 0);
        assert_eq!(config.if_name, "auto");
        assert_eq!(config.if_mtu, 65535);
    }

    #[test]
    fn test_get_address() {
        let config = Config::generate().unwrap();
        let address = config.get_address().unwrap();
        assert_eq!(address.as_bytes()[0], 0x02);
    }

    #[test]
    fn test_multicast_defaults() {
        let config = Config::generate().unwrap();
        assert_eq!(config.multicast_interfaces.len(), 1);
        assert_eq!(config.multicast_interfaces[0].regex, ".*");
        assert!(config.multicast_interfaces[0].beacon);
        assert!(config.multicast_interfaces[0].listen);
    }

    #[test]
    fn test_hjson_with_comments() {
        let config = Config::generate().unwrap();
        let hjson = config.to_hjson_with_comments().unwrap();
        assert!(hjson.contains("Your private key"));
        assert!(hjson.contains("PrivateKey:"));
        assert!(hjson.contains("Peers:"));
        assert!(hjson.contains("MulticastInterfaces:"));
        assert!(hjson.contains("AllowedPublicKeys:"));
        assert!(hjson.contains("IfName:"));
        assert!(hjson.contains("NodeInfo:"));
    }

    /// Test Go configuration compatibility
    ///
    /// Verify that Rust can parse Go-generated configurations
    /// and produce identical address derivations
    #[test]
    fn test_go_config_compatibility() {
        // Go-style HJSON config (PascalCase fields)
        let go_config = r#"{
            PrivateKey: "a3fa855aa6f644e1c7cd3151b0885ca7e95457b9d3b53bfdfac61207ce14abd6e396a2cbd9d5c3dd24360febb53642f082eab058b42ba8b34259816e6d2a4223"
            Peers: []
            Listen: ["tcp://[::]:9001"]
            AdminListen: "tcp://localhost:9001"
            MulticastInterfaces: [
                {
                    Regex: ".*"
                    Beacon: true
                    Listen: true
                }
            ]
            AllowedPublicKeys: []
            IfName: "auto"
            IfMTU: 65535
            NodeInfoPrivacy: false
        }"#;

        // Parse Go config
        let config = Config::parse_from_str(go_config).expect("Should parse Go config");

        // Verify fields
        assert!(config.private_key.is_some());
        assert_eq!(config.peers.len(), 0);
        assert_eq!(config.listen.len(), 1);
        assert_eq!(config.listen[0], "tcp://[::]:9001");
        assert_eq!(
            config.admin_listen,
            Some("tcp://localhost:9001".to_string())
        );
        assert_eq!(config.if_name, "auto");
        assert_eq!(config.if_mtu, 65535);
        assert!(!config.nodeinfo_privacy);

        // Verify address derivation matches expected value
        let addr = config.get_address().expect("Should derive address");
        assert_eq!(addr.to_string(), "200:38d2:ba68:4c54:7845:b793:e028:9593");

        let subnet = config.get_subnet().expect("Should derive subnet");
        assert_eq!(subnet.to_string(), "300:38d2:ba68:4c54::/64");
    }

    /// Test private key format compatibility (32 vs 64 bytes)
    #[test]
    fn test_private_key_format_compatibility() {
        // 32-byte seed only (Rust format)
        let config_32 = r#"{
            PrivateKey: "a3fa855aa6f644e1c7cd3151b0885ca7e95457b9d3b53bfdfac61207ce14abd6"
        }"#;

        // 64-byte seed+public (Go format)
        let config_64 = r#"{
            PrivateKey: "a3fa855aa6f644e1c7cd3151b0885ca7e95457b9d3b53bfdfac61207ce14abd6e396a2cbd9d5c3dd24360febb53642f082eab058b42ba8b34259816e6d2a4223"
        }"#;

        let conf32 = Config::parse_from_str(config_32).expect("Should parse 32-byte key");
        let conf64 = Config::parse_from_str(config_64).expect("Should parse 64-byte key");

        // Both should derive same address
        let addr32 = conf32.get_address().expect("Should derive from 32-byte");
        let addr64 = conf64.get_address().expect("Should derive from 64-byte");

        assert_eq!(
            addr32, addr64,
            "Both key formats should derive same address"
        );
        assert_eq!(addr32.to_string(), "200:38d2:ba68:4c54:7845:b793:e028:9593");
    }

    /// Test round-trip: generate -> serialize -> parse -> verify
    #[test]
    fn test_config_round_trip() {
        // Generate a new config
        let original = Config::generate().expect("Should generate config");
        let original_addr = original.get_address().expect("Should derive address");

        // Serialize to HJSON
        let hjson = original.to_hjson_with_comments().expect("Should serialize");

        // Parse it back
        let parsed = Config::parse_from_str(&hjson).expect("Should parse serialized config");
        let parsed_addr = parsed.get_address().expect("Should derive from parsed");

        // Addresses should match
        assert_eq!(
            original_addr, parsed_addr,
            "Round-trip should preserve address derivation"
        );

        // Config fields should match
        assert_eq!(original.if_name, parsed.if_name);
        assert_eq!(original.if_mtu, parsed.if_mtu);
        assert_eq!(original.nodeinfo_privacy, parsed.nodeinfo_privacy);
    }
}
