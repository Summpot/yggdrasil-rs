//! CLI definitions for yggdrasil command-line interface.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use yggdrasil::VERSION;

/// Yggdrasil mesh networking daemon
#[derive(Parser)]
#[command(name = "yggdrasil")]
#[command(author, version = VERSION, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, short = 'L', default_value = "info", global = true)]
    pub log_level: LogLevel,

    /// Log file path (logs to both console and file)
    #[arg(long, global = true)]
    pub log_file: Option<PathBuf>,

    /// Admin socket endpoint (for admin commands)
    #[arg(
        short = 'e',
        long,
        default_value = "tcp://localhost:9001",
        global = true
    )]
    pub endpoint: String,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Error => write!(f, "error"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Trace => write!(f, "trace"),
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the Yggdrasil daemon
    #[command(alias = "start")]
    Run {
        /// Path to configuration file
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Read configuration from stdin
        #[arg(long)]
        stdin: bool,

        /// Admin socket listen address (overrides config)
        #[arg(short = 'a', long = "admin-listen")]
        admin_listen: Option<String>,

        /// TUN interface name (overrides config)
        #[arg(short = 'n', long = "if-name")]
        if_name: Option<String>,

        /// TUN interface MTU (overrides config)
        #[arg(short = 'm', long = "if-mtu")]
        if_mtu: Option<u64>,

        /// Use automatic configuration (no config file)
        #[arg(long)]
        autoconf: bool,
    },

    /// Generate a new configuration
    #[command(alias = "genconf")]
    GenerateConfig {
        /// Output as JSON instead of HJSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Generate a new key pair
    #[command(alias = "genkeys")]
    GenerateKeys,

    /// Show node information from config
    #[command(alias = "nodeinfo")]
    Info {
        /// Configuration file to extract info from
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Show IPv6 address
        #[arg(short = 'a', long)]
        address: bool,

        /// Show IPv6 subnet
        #[arg(short = 's', long)]
        subnet: bool,

        /// Show public key
        #[arg(short = 'p', long = "public-key", alias = "publickey")]
        public_key: bool,
    },

    /// Normalize/validate a configuration file
    #[command(alias = "normaliseconf")]
    NormalizeConfig {
        /// Configuration file to normalize
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Output as JSON instead of HJSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Export private key in PEM format
    #[command(alias = "exportkey")]
    ExportKey {
        /// Configuration file to export from
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
    },

    // Admin commands (flattened from ctl subcommand)
    /// List available admin commands
    #[command(alias = "list")]
    AdminList {
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Get information about this node
    #[command(alias = "getself")]
    GetSelf {
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Get connected peers
    #[command(alias = "getpeers")]
    GetPeers {
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Get spanning tree
    #[command(alias = "gettree")]
    GetTree {
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Get known paths
    #[command(alias = "getpaths")]
    GetPaths {
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Get active sessions
    #[command(alias = "getsessions")]
    GetSessions {
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Get TUN interface status
    #[command(alias = "gettun")]
    GetTun {
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Add a peer
    #[command(alias = "addpeer")]
    AddPeer {
        /// Peer URI to add
        uri: String,

        /// Source interface
        #[arg(short = 'i', long)]
        interface: Option<String>,
    },

    /// Remove a peer
    #[command(alias = "removepeer")]
    RemovePeer {
        /// Peer URI to remove
        uri: String,

        /// Source interface
        #[arg(short = 'i', long)]
        interface: Option<String>,
    },

    /// Send a raw admin command
    Raw {
        /// Command name
        command: String,

        /// Arguments as key=value pairs
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Manage the Yggdrasil service/daemon
    #[command(name = "service")]
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },

    /// Compatibility mode for yggdrasil-go (same CLI as yggdrasil-go)
    #[command(name = "compat")]
    Compat {
        /// All remaining arguments passed to compat mode
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum ServiceCommand {
    /// Install Yggdrasil as a service
    Install {
        /// Service label/name (e.g. yggdrasil)
        #[arg(long, default_value = "yggdrasil")]
        label: String,

        /// Configuration file to use for the service
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional log file path for the service
        #[arg(long)]
        log_file: Option<PathBuf>,

        /// Log level for the service
        #[arg(long, value_enum, default_value = "info")]
        log_level: LogLevel,

        /// Automatically start the service with the OS
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        autostart: bool,

        /// Install as a user-level service (if supported)
        #[arg(long, action = ArgAction::SetTrue)]
        user: bool,

        /// Run the service as a specific user (platform dependent)
        #[arg(long)]
        username: Option<String>,

        /// Working directory for the service process
        #[arg(long)]
        working_directory: Option<PathBuf>,

        /// Generate a config file if missing
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        generate_config: bool,

        /// Disable automatic restart on failure
        #[arg(long, default_value_t = false, action = ArgAction::SetTrue)]
        disable_restart_on_failure: bool,
    },

    /// Uninstall the service
    Uninstall {
        /// Service label/name
        #[arg(long, default_value = "yggdrasil")]
        label: String,

        /// Target user-level service (if supported)
        #[arg(long, action = ArgAction::SetTrue)]
        user: bool,
    },

    /// Start the service
    Start {
        /// Service label/name
        #[arg(long, default_value = "yggdrasil")]
        label: String,

        /// Target user-level service (if supported)
        #[arg(long, action = ArgAction::SetTrue)]
        user: bool,
    },

    /// Stop the service
    Stop {
        /// Service label/name
        #[arg(long, default_value = "yggdrasil")]
        label: String,

        /// Target user-level service (if supported)
        #[arg(long, action = ArgAction::SetTrue)]
        user: bool,
    },

    /// Show the service status
    Status {
        /// Service label/name
        #[arg(long, default_value = "yggdrasil")]
        label: String,

        /// Target user-level service (if supported)
        #[arg(long, action = ArgAction::SetTrue)]
        user: bool,
    },
}
