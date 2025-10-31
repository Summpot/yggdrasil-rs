#![forbid(unsafe_code)]

mod service;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info};
use std::io::{self, Read};
use yggdrasil_core::{Config, Core};

#[derive(Parser)]
#[command(name = "yggdrasil")]
#[command(about = "Yggdrasil - End-to-end encrypted IPv6 mesh network", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new configuration file
    GenConf {
        /// Output in JSON format (default is HJSON)
        #[arg(short, long)]
        json: bool,
    },
    /// Run the Yggdrasil node
    Run {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,

        /// Use autoconf mode (automatic configuration)
        #[arg(long)]
        autoconf: bool,
    },
    /// Manage Yggdrasil as a system service
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Compatibility command for original Yggdrasil
    #[command(name = "compat")]
    Compat {
        /// Generate configuration (-genconf)
        #[arg(long)]
        genconf: bool,

        /// Use configuration from stdin (-useconf)
        #[arg(long)]
        useconf: bool,

        /// Use configuration from file (-useconffile)
        #[arg(long)]
        useconffile: Option<String>,

        /// Normalize configuration (-normaliseconf)
        #[arg(long)]
        normaliseconf: bool,

        /// Output as JSON instead of HJSON (-json)
        #[arg(long)]
        json: bool,

        /// Show IPv6 address (-address)
        #[arg(long)]
        address: bool,

        /// Show IPv6 subnet (-subnet)
        #[arg(long)]
        subnet: bool,

        /// Show public key (-publickey)
        #[arg(long)]
        publickey: bool,

        /// Export private key in PEM format (-exportkey)
        #[arg(long)]
        exportkey: bool,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install Yggdrasil as a system service
    Install {
        /// Path to configuration file (default: /etc/yggdrasil/config.hjson on Linux)
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Start the Yggdrasil service
    Start,
    /// Stop the Yggdrasil service
    Stop,
    /// Restart the Yggdrasil service
    Restart,
    /// Uninstall the Yggdrasil service
    Uninstall,
    /// Show service status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::GenConf { json }) => gen_conf(json),
        Some(Commands::Run { config, autoconf }) => run(config, autoconf).await,
        Some(Commands::Service { action }) => handle_service(action),
        Some(Commands::Compat {
            genconf,
            useconf,
            useconffile,
            normaliseconf,
            json,
            address,
            subnet,
            publickey,
            exportkey,
        }) => {
            compat(CompatArgs {
                genconf,
                useconf,
                useconffile,
                normaliseconf,
                json,
                address,
                subnet,
                publickey,
                exportkey,
            })
            .await
        }
        None => {
            eprintln!("No command specified. Use --help for usage information.");
            std::process::exit(1);
        }
    }
}

fn gen_conf(json: bool) -> Result<()> {
    let config = Config::generate()?;

    let output = if json {
        serde_json::to_string_pretty(&config)?
    } else {
        config.to_hjson_with_comments()?
    };

    println!("{}", output);
    Ok(())
}

async fn run(config_path: Option<String>, autoconf: bool) -> Result<()> {
    let config = if autoconf {
        info!("Using autoconf mode");
        Config::generate()?
    } else if let Some(path) = config_path {
        info!("Loading configuration from: {}", path);
        Config::from_file(&path)?
    } else {
        error!("No configuration specified. Use --config <file> or --autoconf");
        std::process::exit(1);
    };

    info!("Starting Yggdrasil node...");
    info!("Version: {}", yggdrasil_core::VERSION);

    let core = std::sync::Arc::new(Core::new(config).await?);
    core.clone().start().await?;

    // Wait for shutdown signal (Ctrl+C or SIGTERM)
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully...");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT (Ctrl+C), shutting down gracefully...");
            }
        }
    }
    
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        info!("Received Ctrl+C, shutting down gracefully...");
    }

    core.stop().await?;
    info!("Yggdrasil shutdown complete");
    Ok(())
}

fn handle_service(action: ServiceAction) -> Result<()> {
    match action {
        ServiceAction::Install { config } => {
            info!("Installing Yggdrasil service...");
            service::install_service(config)
        }
        ServiceAction::Start => {
            info!("Starting Yggdrasil service...");
            service::start_service()
        }
        ServiceAction::Stop => {
            info!("Stopping Yggdrasil service...");
            service::stop_service()
        }
        ServiceAction::Restart => {
            info!("Restarting Yggdrasil service...");
            service::restart_service()
        }
        ServiceAction::Uninstall => {
            info!("Uninstalling Yggdrasil service...");
            service::uninstall_service()
        }
        ServiceAction::Status => {
            service::status_service()
        }
    }
}

struct CompatArgs {
    genconf: bool,
    useconf: bool,
    useconffile: Option<String>,
    normaliseconf: bool,
    json: bool,
    address: bool,
    subnet: bool,
    publickey: bool,
    exportkey: bool,
}

async fn compat(args: CompatArgs) -> Result<()> {
    if args.genconf {
        return gen_conf(args.json);
    }

    let config = if args.useconf {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        Config::parse_from_str(&buffer)?
    } else if let Some(path) = args.useconffile {
        Config::from_file(&path)?
    } else if args.normaliseconf {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        Config::parse_from_str(&buffer)?
    } else {
        error!("No configuration specified");
        std::process::exit(1);
    };

    if args.address {
        let addr = config.get_address()?;
        println!("{}", addr);
        return Ok(());
    }

    if args.subnet {
        let subnet = config.get_subnet()?;
        println!("{}", subnet);
        return Ok(());
    }

    if args.publickey {
        let verifying_key = config.get_verifying_key()?;
        println!("{}", hex::encode(verifying_key.to_bytes()));
        return Ok(());
    }

    if args.exportkey {
        let private_key = config.private_key
            .ok_or_else(|| anyhow::anyhow!("No private key in configuration"))?;
        println!("{}", hex::encode(private_key));
        return Ok(());
    }

    if args.normaliseconf {
        let output = if args.json {
            serde_json::to_string_pretty(&config)?
        } else {
            config.to_hjson_with_comments()?
        };
        println!("{}", output);
        return Ok(());
    }

    // Default: run node
    info!("Starting Yggdrasil node (compat mode)...");
    let core = std::sync::Arc::new(Core::new(config).await?);
    core.clone().start().await?;

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    core.stop().await?;
    Ok(())
}
