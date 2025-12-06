//! Main configuration structure.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use yggdrasil_types::PrivateKey;

/// Multicast interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastInterfaceConfig {
    /// Regular expression to match interface names.
    #[serde(rename = "Regex", default)]
    pub regex: String,
    /// Whether to send multicast beacons.
    #[serde(rename = "Beacon", default)]
    pub beacon: bool,
    /// Whether to listen for multicast beacons.
    #[serde(rename = "Listen", default)]
    pub listen: bool,
    /// Port for multicast (0 = random).
    #[serde(rename = "Port", default, skip_serializing_if = "is_zero")]
    pub port: u16,
    /// Priority for this interface.
    #[serde(rename = "Priority", default, skip_serializing_if = "is_zero_u64")]
    pub priority: u64,
    /// Password for multicast peers.
    #[serde(rename = "Password", default)]
    pub password: String,
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

impl Default for MulticastInterfaceConfig {
    fn default() -> Self {
        Self {
            regex: ".*".to_string(),
            beacon: true,
            listen: true,
            port: 0,
            priority: 0,
            password: String::new(),
        }
    }
}

/// Main node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Private key in hex format.
    #[serde(
        rename = "PrivateKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key: Option<String>,

    /// Path to private key file in PEM format.
    #[serde(
        rename = "PrivateKeyPath",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key_path: Option<PathBuf>,

    /// List of outbound peer connection strings.
    #[serde(rename = "Peers", default)]
    pub peers: Vec<String>,

    /// Peer connections arranged by source interface.
    #[serde(
        rename = "InterfacePeers",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub interface_peers: HashMap<String, Vec<String>>,

    /// Listen addresses for incoming connections.
    #[serde(rename = "Listen", default)]
    pub listen: Vec<String>,

    /// Listen address for admin connections.
    #[serde(
        rename = "AdminListen",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub admin_listen: String,

    /// Configuration for multicast interfaces.
    #[serde(rename = "MulticastInterfaces", default)]
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,

    /// List of allowed peer public keys.
    #[serde(rename = "AllowedPublicKeys", default)]
    pub allowed_public_keys: Vec<String>,

    /// Network interface name for TUN adapter.
    #[serde(rename = "IfName", default)]
    pub if_name: String,

    /// MTU size for TUN interface.
    #[serde(rename = "IfMTU", default)]
    pub if_mtu: u64,

    /// Whether to log lookups.
    #[serde(
        rename = "LogLookups",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub log_lookups: bool,

    /// Whether to enable nodeinfo privacy.
    #[serde(rename = "NodeInfoPrivacy", default)]
    pub node_info_privacy: bool,

    /// Optional nodeinfo.
    #[serde(rename = "NodeInfo", default, skip_serializing_if = "Option::is_none")]
    pub node_info: Option<serde_json::Value>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self::generate()
    }
}

impl NodeConfig {
    /// Generate a new configuration with default values.
    /// This matches yggdrasil-go's GenerateConfig() behavior.
    pub fn generate() -> Self {
        let defaults = crate::get_defaults();
        let private_key = PrivateKey::generate();

        Self {
            private_key: Some(hex::encode(private_key.as_bytes())),
            private_key_path: None,
            peers: Vec::new(),
            interface_peers: HashMap::new(),
            listen: Vec::new(),
            admin_listen: String::new(), // Match yggdrasil-go: AdminListen is empty in genconf
            multicast_interfaces: defaults.default_multicast_interfaces,
            allowed_public_keys: Vec::new(),
            if_name: defaults.default_if_name,
            if_mtu: defaults.default_if_mtu,
            log_lookups: false,
            node_info_privacy: false,
            node_info: Some(serde_json::json!({})), // Match yggdrasil-go: empty object
        }
    }

    /// Parse configuration from HJSON bytes.
    pub fn from_hjson(data: &[u8]) -> Result<Self, ConfigError> {
        // Handle BOM
        let data = Self::strip_bom(data);

        // Parse HJSON
        let text = std::str::from_utf8(data).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let mut config: Self =
            serde_hjson::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;

        // Post-process
        config.postprocess()?;

        Ok(config)
    }

    /// Parse configuration from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, ConfigError> {
        let mut config: Self =
            serde_json::from_slice(data).map_err(|e| ConfigError::Parse(e.to_string()))?;

        config.postprocess()?;

        Ok(config)
    }

    /// Serialize configuration to HJSON.
    pub fn to_hjson(&self) -> Result<String, ConfigError> {
        serde_hjson::to_string(self).map_err(|e| ConfigError::Serialize(e.to_string()))
    }

    /// Serialize configuration to HJSON with comments (matching yggdrasil-go format).
    pub fn to_hjson_with_comments(&self) -> Result<String, ConfigError> {
        // Build HJSON manually with comments to match yggdrasil-go output
        let mut output = String::new();
        output.push_str("{\n");

        // PrivateKey
        if let Some(ref key) = self.private_key {
            output.push_str("  # Your private key. DO NOT share this with anyone!\n");
            output.push_str(&format!("  PrivateKey: {}\n", key));
        }

        // Peers
        output
            .push_str("\n  # List of outbound peer connection strings (e.g. tls://a.b.c.d:e or\n");
        output.push_str(
            "  # socks://a.b.c.d:e/f.g.h.i:j). Connection strings can contain options,\n",
        );
        output
            .push_str("  # see https://yggdrasil-network.github.io/configurationref.html#peers.\n");
        output.push_str("  # Yggdrasil has no concept of bootstrap nodes - all network traffic\n");
        output
            .push_str("  # will transit peer connections. Therefore make sure to only peer with\n");
        output.push_str(
            "  # nearby nodes that have good connectivity and low latency. Avoid adding\n",
        );
        output.push_str("  # peers to this list from distant countries as this will worsen your\n");
        output.push_str("  # node's connectivity and performance considerably.\n");
        output.push_str("  Peers: [");
        if self.peers.is_empty() {
            output.push_str("]\n");
        } else {
            output.push('\n');
            for peer in &self.peers {
                output.push_str(&format!("    {}\n", peer));
            }
            output.push_str("  ]\n");
        }

        // InterfacePeers
        if !self.interface_peers.is_empty() {
            output.push_str(
                "\n  # List of connection strings for outbound peer connections in URI format,\n",
            );
            output.push_str(
                "  # arranged by source interface, e.g. { \"eth0\": [ \"tls://a.b.c.d:e\" ] }.\n",
            );
            output.push_str(
                "  # You should only use this option if your machine is multi-homed and you\n",
            );
            output.push_str(
                "  # want to establish outbound peer connections on different interfaces.\n",
            );
            output.push_str("  # Otherwise you should use \"Peers\".\n");
            output.push_str("  InterfacePeers:\n");
            output.push_str("  {\n");
            for (iface, peers) in &self.interface_peers {
                output.push_str(&format!("    {}: [\n", iface));
                for peer in peers {
                    output.push_str(&format!("      {}\n", peer));
                }
                output.push_str("    ]\n");
            }
            output.push_str("  }\n");
        }

        // Listen
        output.push_str("\n  # Listen addresses for incoming connections. You will need to add\n");
        output
            .push_str("  # listeners in order to accept incoming peerings from non-local nodes.\n");
        output.push_str(
            "  # This is not required if you wish to establish outbound peerings only.\n",
        );
        output.push_str("  # Multicast peer discovery will work regardless of any listeners set\n");
        output
            .push_str("  # here. Each listener should be specified in URI format as above, e.g.\n");
        output.push_str("  # tls://0.0.0.0:0 or tls://[::]:0 to listen on all interfaces.\n");
        output.push_str("  Listen: [");
        if self.listen.is_empty() {
            output.push_str("]\n");
        } else {
            output.push('\n');
            for addr in &self.listen {
                output.push_str(&format!("    {}\n", addr));
            }
            output.push_str("  ]\n");
        }

        // AdminListen
        output.push_str(
            "\n  # Listen address for admin connections. Default is to listen for local\n",
        );
        output.push_str("  # connections either on TCP/9001 or a UNIX socket depending on your\n");
        output.push_str("  # platform. Use this value for yggdrasilctl -endpoint=X. To disable\n");
        output.push_str("  # the admin socket, use the value \"none\" instead.\n");
        if self.admin_listen.is_empty() {
            output.push_str("  AdminListen: \"\"\n");
        } else {
            output.push_str(&format!("  AdminListen: {}\n", self.admin_listen));
        }

        // MulticastInterfaces
        output.push_str(
            "\n  # Configuration for which interfaces multicast peer discovery should be\n",
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
        output
            .push_str("  # listens out for and tries to connect to other advertising nodes. See\n");
        output.push_str(
            "  # https://yggdrasil-network.github.io/configurationref.html#multicastinterfaces\n",
        );
        output.push_str("  # for more supported options.\n");
        output.push_str("  MulticastInterfaces:\n");
        output.push_str("  [\n");
        for iface in &self.multicast_interfaces {
            output.push_str("    {\n");
            output.push_str(&format!("      Regex: {}\n", iface.regex));
            output.push_str(&format!("      Beacon: {}\n", iface.beacon));
            output.push_str(&format!("      Listen: {}\n", iface.listen));
            if iface.port != 0 {
                output.push_str(&format!("      Port: {}\n", iface.port));
            }
            if iface.priority != 0 {
                output.push_str(&format!("      Priority: {}\n", iface.priority));
            }
            output.push_str(&format!("      Password: \"{}\"\n", iface.password));
            output.push_str("    }\n");
        }
        output.push_str("  ]\n");

        // AllowedPublicKeys
        output.push_str("\n  # List of peer public keys to allow incoming peering connections\n");
        output.push_str("  # from. If left empty/undefined then all connections will be allowed\n");
        output.push_str("  # by default. This does not affect outgoing peerings, nor does it\n");
        output.push_str("  # affect link-local peers discovered via multicast.\n");
        output.push_str("  # WARNING: THIS IS NOT A FIREWALL and DOES NOT limit who can reach\n");
        output.push_str("  # open ports or services running on your machine!\n");
        output.push_str("  AllowedPublicKeys: [");
        if self.allowed_public_keys.is_empty() {
            output.push_str("]\n");
        } else {
            output.push('\n');
            for key in &self.allowed_public_keys {
                output.push_str(&format!("    {}\n", key));
            }
            output.push_str("  ]\n");
        }

        // IfName
        output.push_str(
            "\n  # Local network interface name for TUN adapter, or \"auto\" to select\n",
        );
        output.push_str("  # an interface automatically, or \"none\" to run without TUN.\n");
        output.push_str(&format!("  IfName: {}\n", self.if_name));

        // IfMTU
        output
            .push_str("\n  # Maximum Transmission Unit (MTU) size for your local TUN interface.\n");
        output
            .push_str("  # Default is the largest supported size for your platform. The lowest\n");
        output.push_str("  # possible value is 1280.\n");
        output.push_str(&format!("  IfMTU: {}\n", self.if_mtu));

        // NodeInfoPrivacy
        output.push_str(
            "\n  # By default, nodeinfo contains some defaults including the platform,\n",
        );
        output.push_str("  # architecture and Yggdrasil version. These can help when surveying\n");
        output.push_str("  # the network and diagnosing network routing problems. Enabling\n");
        output.push_str("  # nodeinfo privacy prevents this, so that only items specified in\n");
        output.push_str("  # \"NodeInfo\" are sent back if specified.\n");
        output.push_str(&format!("  NodeInfoPrivacy: {}\n", self.node_info_privacy));

        // NodeInfo
        output
            .push_str("\n  # Optional nodeinfo. This must be a { \"key\": \"value\", ... } map\n");
        output.push_str("  # or set as null. This is entirely optional but, if set, is visible\n");
        output.push_str("  # to the whole network on request.\n");
        match &self.node_info {
            Some(v) => {
                let json_str = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
                output.push_str(&format!("  NodeInfo: {}\n", json_str));
            }
            None => {
                output.push_str("  NodeInfo: {}\n");
            }
        }

        output.push_str("}\n");

        Ok(output)
    }

    /// Serialize configuration to JSON.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self).map_err(|e| ConfigError::Serialize(e.to_string()))
    }

    /// Strip byte order mark if present.
    fn strip_bom(data: &[u8]) -> &[u8] {
        if data.len() >= 3 && &data[0..3] == b"\xEF\xBB\xBF" {
            &data[3..]
        } else if data.len() >= 2 {
            if &data[0..2] == b"\xFF\xFE" || &data[0..2] == b"\xFE\xFF" {
                // UTF-16 BOM - this would need proper handling
                tracing::warn!("UTF-16 encoded config files are not fully supported");
                data
            } else {
                data
            }
        } else {
            data
        }
    }

    /// Post-process the configuration after parsing.
    fn postprocess(&mut self) -> Result<(), ConfigError> {
        // If private_key_path is set, load the key from that file
        if let Some(ref path) = self.private_key_path {
            let pem_data = std::fs::read(path).map_err(|e| ConfigError::KeyFile(e.to_string()))?;
            let key_hex = Self::parse_pem_private_key(&pem_data)?;
            self.private_key = Some(key_hex);
        }

        // Ensure we have a private key
        if self.private_key.is_none() {
            let key = PrivateKey::generate();
            self.private_key = Some(hex::encode(key.as_bytes()));
        }

        Ok(())
    }

    /// Parse a PEM-encoded private key.
    fn parse_pem_private_key(pem_data: &[u8]) -> Result<String, ConfigError> {
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|_| ConfigError::KeyFile("Invalid UTF-8 in PEM file".to_string()))?;

        // Simple PEM parsing
        let start = pem_str
            .find("-----BEGIN PRIVATE KEY-----")
            .ok_or_else(|| ConfigError::KeyFile("No PRIVATE KEY header found".to_string()))?;
        let end = pem_str
            .find("-----END PRIVATE KEY-----")
            .ok_or_else(|| ConfigError::KeyFile("No PRIVATE KEY footer found".to_string()))?;

        let base64_data: String = pem_str[start + 27..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        // Decode base64
        let der = base64::decode(&base64_data)
            .map_err(|e| ConfigError::KeyFile(format!("Invalid base64: {}", e)))?;

        // For Ed25519 PKCS8, the key is at a specific offset
        // PKCS8 structure: SEQUENCE { version, algorithm, key }
        // The actual Ed25519 key is 32 bytes near the end
        if der.len() < 48 {
            return Err(ConfigError::KeyFile("PKCS8 data too short".to_string()));
        }

        // The private key seed is typically at offset 16 in the PKCS8 structure
        // and is 32 bytes
        // Full Ed25519 private key is 64 bytes (seed + public)
        let seed = &der[der.len() - 32..];

        // Generate the full private key from the seed
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(
            seed.try_into()
                .map_err(|_| ConfigError::KeyFile("Invalid key length".to_string()))?,
        );
        let full_key = signing_key.to_keypair_bytes();

        Ok(hex::encode(full_key))
    }

    /// Get the private key.
    pub fn get_private_key(&self) -> Result<PrivateKey, ConfigError> {
        let hex_str = self.private_key.as_ref().ok_or(ConfigError::MissingKey)?;

        let bytes = hex::decode(hex_str).map_err(|e| ConfigError::InvalidKey(e.to_string()))?;

        PrivateKey::from_bytes(&bytes).map_err(|e| ConfigError::InvalidKey(format!("{:?}", e)))
    }
}

/// Base64 decoding helper.
mod base64 {
    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = Vec::with_capacity(input.len() * 3 / 4);
        let mut buffer: u32 = 0;
        let mut bits_collected = 0;

        for c in input.bytes() {
            if c == b'=' {
                break;
            }

            let value = table
                .iter()
                .position(|&x| x == c)
                .ok_or_else(|| format!("Invalid base64 character: {}", c as char))?;

            buffer = (buffer << 6) | (value as u32);
            bits_collected += 6;

            if bits_collected >= 8 {
                bits_collected -= 8;
                output.push((buffer >> bits_collected) as u8);
                buffer &= (1 << bits_collected) - 1;
            }
        }

        Ok(output)
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to parse configuration: {0}")]
    Parse(String),
    #[error("failed to serialize configuration: {0}")]
    Serialize(String),
    #[error("failed to read key file: {0}")]
    KeyFile(String),
    #[error("missing private key")]
    MissingKey,
    #[error("invalid private key: {0}")]
    InvalidKey(String),
}
