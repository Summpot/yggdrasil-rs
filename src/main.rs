//! Yggdrasil network daemon.
//!
//! A modern CLI for the Yggdrasil mesh networking daemon.
//! Supports both legacy yggdrasil-go compatible mode and modern subcommand-based usage.

mod admin_commands;
mod cli;
mod service;
mod utils;

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tracing_subscriber::Layer;

use anyhow::{Context, Result};
use clap::Parser;
use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use yggdrasil::{AdminServer, Core, NodeConfig, VERSION};
use yggdrasil_address::Address;
use yggdrasil_config::get_defaults;
use yggdrasil_link::{LinkType, Links, LinksListenerFactory, OutgoingPacket};
use yggdrasil_multicast::{
    Multicast, MulticastConfig, MulticastInterfaceConfig as MulticastIfaceConfig,
};
use yggdrasil_tun::{TunAdapter, TunConfig};
use yggdrasil_types::PublicKey;
use yggdrasil_wire::{Traffic, WireEncode, WirePacketType};

use cli::{Cli, Commands};

/// Registry for tracking peer outgoing channels.
type PeerRegistry = Arc<DashMap<PublicKey, mpsc::UnboundedSender<OutgoingPacket>>>;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Check for compat mode first (before setting up logging)
    if let Some(Commands::Compat { args }) = &cli.command {
        return run_compat_mode(args);
    }

    // Install the ring crypto provider for rustls
    // This is required because rustls doesn't auto-detect the provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize tracing
    // Build filter for console that respects RUST_LOG env var, with CLI flag as fallback
    // Always reduce multicast module logs to trace level
    let default_console_filter = format!(
        "{},yggdrasil_multicast::multicast=error",
        cli.log_level
    );
    let console_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&default_console_filter));

    // Create console layer with its filter
    let console_layer = tracing_subscriber::fmt::layer()
        .with_filter(console_filter);

    // Optionally create file layer with trace-level filter
    if let Some(log_file) = &cli.log_file {
        // Use RollingFileAppender for better log management
        let file_dir = log_file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let file_name = log_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("yggdrasil.log");
        
        let file_appender = tracing_appender::rolling::never(file_dir, file_name);
        
        // File layer always uses trace level, but also respects RUST_LOG if set
        let file_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| {
                // Default file filter: trace for everything
                tracing_subscriber::EnvFilter::new("trace")
            });
        
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(file_appender)
            .with_ansi(false)
            .with_filter(file_filter);

        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(console_layer)
            .init();
    }

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let endpoint = &cli.endpoint;
    match cli.command {
        Some(Commands::Run {
            config,
            stdin,
            admin_listen,
            if_name,
            if_mtu,
            autoconf,
        }) => cmd_run(config, stdin, admin_listen, if_name, if_mtu, autoconf),
        Some(Commands::GenerateConfig { json }) => cmd_generate_config(json),
        Some(Commands::GenerateKeys) => cmd_generate_keys(),
        Some(Commands::Info {
            config,
            address,
            subnet,
            public_key,
        }) => cmd_info(config, address, subnet, public_key),
        Some(Commands::NormalizeConfig { config, json }) => cmd_normalize_config(config, json),
        Some(Commands::ExportKey { config }) => cmd_export_key(config),
        // Admin commands (flattened)
        Some(Commands::AdminList { json }) => admin_commands::ctl_list(endpoint, json),
        Some(Commands::GetSelf { json }) => admin_commands::ctl_get_self(endpoint, json),
        Some(Commands::GetPeers { json }) => admin_commands::ctl_get_peers(endpoint, json),
        Some(Commands::GetTree { json }) => admin_commands::ctl_get_tree(endpoint, json),
        Some(Commands::GetPaths { json }) => admin_commands::ctl_get_paths(endpoint, json),
        Some(Commands::GetSessions { json }) => admin_commands::ctl_get_sessions(endpoint, json),
        Some(Commands::GetTun { json }) => admin_commands::ctl_get_tun(endpoint, json),
        Some(Commands::AddPeer { uri, interface }) => {
            admin_commands::ctl_add_peer(endpoint, &uri, interface.as_deref())
        }
        Some(Commands::RemovePeer { uri, interface }) => {
            admin_commands::ctl_remove_peer(endpoint, &uri, interface.as_deref())
        }
        Some(Commands::Raw { command, args }) => admin_commands::ctl_raw(endpoint, &command, &args),
        Some(Commands::Service { action }) => service::handle_service_command(action),
        Some(Commands::Compat { .. }) => unreachable!(), // Handled above
        None => {
            // Default: show help
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

fn cmd_run(
    config_path: Option<PathBuf>,
    use_stdin: bool,
    admin_listen_override: Option<String>,
    if_name_override: Option<String>,
    if_mtu_override: Option<u64>,
    autoconf: bool,
) -> Result<()> {
    let mut config = if autoconf {
        NodeConfig::generate()
    } else if let Some(ref path) = config_path {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        NodeConfig::from_hjson(&data)?
    } else if use_stdin || !utils::atty::is(utils::atty::Stream::Stdin) {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        if !data.is_empty() {
            NodeConfig::from_hjson(&data)?
        } else {
            NodeConfig::generate()
        }
    } else {
        NodeConfig::generate()
    };

    // Apply command-line overrides
    if let Some(admin_listen) = admin_listen_override {
        config.admin_listen = admin_listen;
    }
    if let Some(if_name) = if_name_override {
        config.if_name = if_name;
    }
    if let Some(if_mtu) = if_mtu_override {
        config.if_mtu = if_mtu;
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run_daemon(config).await })
}

async fn run_daemon(config: NodeConfig) -> Result<()> {
    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Get platform defaults for values not specified in config
    let defaults = get_defaults();

    // Create the core
    let core = Arc::new(Core::new(&config)?);

    tracing::info!(
        address = %core.address(),
        subnet = %core.subnet(),
        public_key = %hex::encode(core.public_key().as_bytes()),
        "Starting Yggdrasil"
    );

    core.start().await?;

    // Start admin server
    // If admin_listen is empty in config, use platform default
    let admin_listen = if config.admin_listen.is_empty() {
        defaults.default_admin_listen.clone()
    } else {
        config.admin_listen.clone()
    };

    let admin_server = if !admin_listen.is_empty() && admin_listen != "none" {
        let server = Arc::new(AdminServer::new(&admin_listen, Arc::clone(&core)));
        server.setup_handlers();
        server.start().await?;
        tracing::info!(listen = %admin_listen, "Admin socket started");
        Some(server)
    } else {
        tracing::debug!("Admin socket disabled");
        None
    };

    // Start links manager
    let links_result = start_links(&config, &core).await?;
    let (links, peer_registry, incoming_rx) = match links_result {
        Some((l, r, rx)) => (Some(l), Some(r), Some(rx)),
        None => (None, None, None),
    };

    // Connect links to admin server
    if let (Some(admin), Some(links_arc)) = (&admin_server, &links) {
        admin.set_links(Arc::clone(links_arc));
    }

    // Start multicast module
    let multicast = start_multicast(&config, &core, links.as_ref()).await?;

    // Start TUN adapter
    let tun_adapter =
        start_tun_adapter(&config, &core, admin_server.as_ref(), peer_registry, incoming_rx).await?;

    // Setup graceful shutdown
    let shutdown_tx_clone = shutdown_tx.clone();

    // Handle multiple shutdown signals
    tokio::spawn(async move {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received Ctrl+C, initiating shutdown...");
            }
            _ = terminate => {
                tracing::info!("Received SIGTERM, initiating shutdown...");
            }
        }

        let _ = shutdown_tx_clone.send(());
    });

    // Wait for shutdown signal
    let mut shutdown_rx = shutdown_tx.subscribe();
    shutdown_rx.recv().await.ok();

    tracing::info!("Shutting down gracefully...");

    // Stop multicast
    if let Some(mc) = multicast {
        mc.stop();
        tracing::debug!("Multicast module stopped");
    }

    // Stop links
    if let Some(l) = links {
        l.stop();
        tracing::debug!("Links module stopped");
    }

    // Stop TUN adapter
    if let Some(tun) = tun_adapter {
        if let Err(e) = tun.stop().await {
            tracing::warn!(error = %e, "Error stopping TUN adapter");
        }
    }

    // Stop admin server
    if let Some(admin) = admin_server {
        if let Err(e) = admin.stop().await {
            tracing::warn!(error = %e, "Error stopping admin server");
        }
    }

    // Stop core
    core.stop().await?;

    tracing::info!("Shutdown complete");
    Ok(())
}

/// Start the links manager for peer connections.
/// Returns (Links, PeerRegistry, IncomingPacketReceiver)
async fn start_links(
    config: &NodeConfig,
    core: &Arc<Core>,
) -> Result<Option<(Arc<Links>, PeerRegistry, mpsc::UnboundedReceiver<Vec<u8>>)>> {
    let private_key = config.get_private_key()?;
    let (links, mut event_rx) = Links::new(private_key);
    let links = Arc::new(links);

    // Start the links manager
    if let Err(e) = links.start().await {
        tracing::warn!(error = %e, "Failed to start links manager");
        return Ok(None);
    }

    // Set allowed public keys if configured
    let allowed_keys: Vec<_> = config
        .allowed_public_keys
        .iter()
        .filter_map(|hex_key| {
            hex::decode(hex_key)
                .ok()
                .and_then(|bytes| yggdrasil_types::PublicKey::from_bytes(&bytes).ok())
        })
        .collect();
    links.set_allowed_keys(allowed_keys);

    tracing::info!("Links manager started");

    // Create peer registry for tracking outgoing channels
    let peer_registry: PeerRegistry = Arc::new(DashMap::new());
    let peer_registry_clone = Arc::clone(&peer_registry);
    
    // Create channel for incoming decrypted packets to be written to TUN
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Clone core for the peer event handler
    let core_clone = Arc::clone(core);

    // Spawn a task to handle peer connection events
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let dir = if event.outbound {
                "outbound"
            } else {
                "inbound"
            };
            tracing::info!(
                peer = %hex::encode(&event.public_key.as_bytes()[..8]),
                addr = %event.ipv6_addr,
                remote = %event.remote_addr,
                local = %event.local_addr,
                direction = dir,
                peer_port = event.peer_port,
                "Peer connected"
            );

            // Register the outgoing channel for this peer
            peer_registry_clone.insert(event.public_key, event.outgoing_tx);

            // Spawn a task to handle events from this peer
            let _peer_key = event.public_key;
            let peer_registry_inner = Arc::clone(&peer_registry_clone);
            let core_for_peer = Arc::clone(&core_clone);
            let incoming_tx_for_peer = incoming_tx.clone();
            let mut peer_event_rx = event.event_rx;
            tokio::spawn(async move {
                while let Some(peer_event) = peer_event_rx.recv().await {
                    match peer_event {
                        yggdrasil_link::PeerEvent::SigRequest { from, req } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                seq = req.seq,
                                nonce = req.nonce,
                                "Received signature request"
                            );
                        }
                        yggdrasil_link::PeerEvent::SigResponse { from, res, rtt } => {
                            tracing::debug!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                seq = res.req.seq,
                                port = res.port,
                                rtt_ms = rtt.as_millis(),
                                "Received signature response"
                            );
                        }
                        yggdrasil_link::PeerEvent::Announce { from, announce } => {
                            tracing::debug!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                key = %hex::encode(&announce.key.as_bytes()[..8]),
                                parent = %hex::encode(&announce.parent.as_bytes()[..8]),
                                port = announce.sig_res.port,
                                "Received router announcement"
                            );
                        }
                        yggdrasil_link::PeerEvent::Traffic { from, traffic } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                source = %hex::encode(&traffic.source.as_bytes()[..8]),
                                dest = %hex::encode(&traffic.dest.as_bytes()[..8]),
                                payload_len = traffic.payload.len(),
                                "Received traffic"
                            );
                            
                            // Decrypt the traffic payload using session manager
                            let sessions = core_for_peer.sessions();
                            match sessions.handle_data(&from, &traffic.payload) {
                                yggdrasil_session::HandleResult::Received { payload } => {
                                    tracing::debug!(
                                        from = %hex::encode(&from.as_bytes()[..8]),
                                        payload_len = payload.len(),
                                        "Decrypted incoming traffic"
                                    );
                                    // Send the decrypted IPv6 packet to TUN
                                    if let Err(e) = incoming_tx_for_peer.send(payload) {
                                        tracing::debug!(
                                            error = %e,
                                            "Failed to send decrypted packet to TUN channel"
                                        );
                                    }
                                }
                                yggdrasil_session::HandleResult::SendInit { dest, init } => {
                                    // Need to send init message back
                                    tracing::debug!(
                                        dest = %hex::encode(&dest.as_bytes()[..8]),
                                        "Need to send session init"
                                    );
                                    if let Some(init_data) = sessions.encrypt_init(&dest, &init) {
                                        let init_traffic = yggdrasil_wire::Traffic::new(
                                            *core_for_peer.public_key(),
                                            dest,
                                            init_data
                                        );
                                        if let Some(tx) = peer_registry_inner.get(&dest) {
                                            let mut payload = Vec::new();
                                            if init_traffic.wire_encode(&mut payload).is_ok() {
                                                let packet = yggdrasil_link::OutgoingPacket {
                                                    packet_type: yggdrasil_wire::WirePacketType::Traffic,
                                                    payload,
                                                };
                                                let _ = tx.send(packet);
                                            }
                                        }
                                    }
                                }
                                yggdrasil_session::HandleResult::SendAck { dest, ack, buffered_data } => {
                                    // Need to send ack message back
                                    tracing::debug!(
                                        dest = %hex::encode(&dest.as_bytes()[..8]),
                                        has_buffered = buffered_data.is_some(),
                                        "Need to send session ack"
                                    );
                                    if let Some(ack_data) = sessions.encrypt_ack(&dest, &ack) {
                                        let ack_traffic = yggdrasil_wire::Traffic::new(
                                            *core_for_peer.public_key(),
                                            dest,
                                            ack_data
                                        );
                                        if let Some(tx) = peer_registry_inner.get(&dest) {
                                            let mut payload = Vec::new();
                                            if ack_traffic.wire_encode(&mut payload).is_ok() {
                                                let packet = yggdrasil_link::OutgoingPacket {
                                                    packet_type: yggdrasil_wire::WirePacketType::Traffic,
                                                    payload,
                                                };
                                                let _ = tx.send(packet);
                                            }
                                        }
                                    }
                                    // Also send buffered data to TUN if any
                                    if let Some(data) = buffered_data {
                                        if let Err(e) = incoming_tx_for_peer.send(data) {
                                            tracing::debug!(
                                                error = %e,
                                                "Failed to send buffered packet to TUN channel"
                                            );
                                        }
                                    }
                                }
                                yggdrasil_session::HandleResult::SendBuffered { dest, data } => {
                                    // Need to send buffered data
                                    tracing::debug!(
                                        dest = %hex::encode(&dest.as_bytes()[..8]),
                                        data_len = data.len(),
                                        "Need to send buffered data"
                                    );
                                    let buffered_traffic = yggdrasil_wire::Traffic::new(
                                        *core_for_peer.public_key(),
                                        dest,
                                        data
                                    );
                                    if let Some(tx) = peer_registry_inner.get(&dest) {
                                        let mut payload = Vec::new();
                                        if buffered_traffic.wire_encode(&mut payload).is_ok() {
                                            let packet = yggdrasil_link::OutgoingPacket {
                                                packet_type: yggdrasil_wire::WirePacketType::Traffic,
                                                payload,
                                            };
                                            let _ = tx.send(packet);
                                        }
                                    }
                                }
                                yggdrasil_session::HandleResult::Ignored => {
                                    tracing::trace!("Ignored traffic packet (possibly dummy)");
                                }
                                yggdrasil_session::HandleResult::Error => {
                                    tracing::debug!(
                                        from = %hex::encode(&from.as_bytes()[..8]),
                                        "Error handling traffic packet"
                                    );
                                }
                            }
                        }
                        yggdrasil_link::PeerEvent::BloomFilter { from, data } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                data_len = data.len(),
                                "Received bloom filter update"
                            );
                        }
                        yggdrasil_link::PeerEvent::PathLookup { from, lookup } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                source = %hex::encode(&lookup.source.as_bytes()[..8]),
                                dest = %hex::encode(&lookup.dest.as_bytes()[..8]),
                                "Received path lookup"
                            );
                        }
                        yggdrasil_link::PeerEvent::PathNotify { from, notify } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                source = %hex::encode(&notify.source.as_bytes()[..8]),
                                dest = %hex::encode(&notify.dest.as_bytes()[..8]),
                                "Received path notify"
                            );
                        }
                        yggdrasil_link::PeerEvent::PathBroken { from, broken } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                source = %hex::encode(&broken.source.as_bytes()[..8]),
                                dest = %hex::encode(&broken.dest.as_bytes()[..8]),
                                "Received path broken"
                            );
                        }
                        yggdrasil_link::PeerEvent::Disconnected { key, error } => {
                            tracing::info!(
                                peer = %hex::encode(&key.as_bytes()[..8]),
                                error = ?error,
                                "Peer disconnected"
                            );
                            // Remove peer from registry
                            peer_registry_inner.remove(&key);
                            break;
                        }
                    }
                }
            });
        }
    });

    Ok(Some((links, peer_registry, incoming_rx)))
}

async fn start_multicast(
    config: &NodeConfig,
    core: &Arc<Core>,
    links: Option<&Arc<Links>>,
) -> Result<Option<Arc<Multicast>>> {
    // Build multicast config from node config
    let mut interfaces = Vec::new();

    for iface_cfg in &config.multicast_interfaces {
        match MulticastIfaceConfig::new(&iface_cfg.regex, iface_cfg.beacon, iface_cfg.listen) {
            Ok(cfg) => {
                let cfg = cfg
                    .with_port(iface_cfg.port)
                    .with_priority(iface_cfg.priority as u8)
                    .with_password(iface_cfg.password.clone());
                interfaces.push(cfg);
            }
            Err(e) => {
                tracing::warn!(regex = %iface_cfg.regex, error = %e, "Invalid multicast interface regex");
            }
        }
    }

    if interfaces.is_empty() {
        tracing::info!("No multicast interfaces configured");
        return Ok(None);
    }

    let mc_config = MulticastConfig {
        interfaces,
        group_addr: "[ff02::114]:9001".to_string(),
    };

    let (multicast, mut peer_rx) = Multicast::new(core.public_key().clone(), mc_config);

    let multicast = Arc::new(multicast);

    // Set the listener factory so multicast can create TLS listeners on-demand
    if let Some(links) = links {
        let factory = LinksListenerFactory::new(Arc::clone(links));
        multicast.set_listener_factory(Arc::new(factory));
    }

    // Start the multicast module
    if let Err(e) = multicast.clone().start().await {
        tracing::warn!(error = %e, "Failed to start multicast module");
        return Ok(None);
    }

    tracing::info!("Multicast module started");

    // Spawn a task to handle discovered peers
    let links_clone = links.cloned();
    tokio::spawn(async move {
        while let Some(event) = peer_rx.recv().await {
            tracing::info!(
                peer = %hex::encode(&event.public_key.as_bytes()[..8]),
                addr = %event.addr,
                interface = %event.interface,
                "Discovered peer via multicast"
            );

            // Connect to the discovered peer
            if let Some(ref links) = links_clone {
                let links = Arc::clone(links);
                let addr = event.addr;
                let password = event.password.into_bytes();
                let priority = event.priority;

                tokio::spawn(async move {
                    match links
                        .connect(
                            addr,
                            "", // No source interface constraint
                            LinkType::Ephemeral,
                            priority,
                            &password,
                        )
                        .await
                    {
                        Ok(remote_key) => {
                            tracing::debug!(
                                peer = %hex::encode(&remote_key.as_bytes()[..8]),
                                addr = %addr,
                                "Connected to multicast peer"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                addr = %addr,
                                error = %e,
                                "Failed to connect to multicast peer"
                            );
                        }
                    }
                });
            }
        }
    });

    Ok(Some(multicast))
}

async fn start_tun_adapter(
    config: &NodeConfig,
    core: &Arc<Core>,
    admin_server: Option<&Arc<AdminServer>>,
    peer_registry: Option<PeerRegistry>,
    incoming_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
) -> Result<Option<Arc<TunAdapter>>> {
    let if_name = if config.if_name.is_empty() {
        "auto".to_string()
    } else {
        config.if_name.clone()
    };

    // Check if TUN is disabled
    if if_name == "none" || if_name == "dummy" {
        tracing::info!("TUN adapter disabled");
        if let Some(admin) = admin_server {
            admin.set_tun_info(None, None, false);
        }
        return Ok(None);
    }

    let if_mtu = if config.if_mtu == 0 {
        65535
    } else {
        config.if_mtu as u16
    };

    let tun_config = TunConfig {
        name: if_name.clone(),
        mtu: if_mtu,
    };

    let tun = Arc::new(TunAdapter::new(
        core.address().clone(),
        core.subnet().clone(),
        tun_config,
    ));

    match tun.start().await {
        Ok(()) => {
            tracing::info!(name = if_name, mtu = if_mtu, "TUN adapter started");

            // Update admin server with TUN info
            if let Some(admin) = admin_server {
                admin.set_tun_info(Some(if_name), Some(if_mtu as u64), true);
            }

            // Spawn TUN read loop (outgoing packets)
            let tun_clone = Arc::clone(&tun);
            let core_clone = Arc::clone(core);
            tokio::spawn(async move {
                tun_read_loop(tun_clone, core_clone, peer_registry).await;
            });
            
            // Spawn TUN write loop (incoming packets from peers)
            if let Some(rx) = incoming_rx {
                let tun_clone = Arc::clone(&tun);
                tokio::spawn(async move {
                    tun_write_loop(tun_clone, rx).await;
                });
            }

            Ok(Some(tun))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to start TUN adapter");
            if let Some(admin) = admin_server {
                admin.set_tun_info(None, None, false);
            }
            // Don't fail the daemon if TUN fails, just log the error
            Ok(None)
        }
    }
}

async fn tun_read_loop(tun: Arc<TunAdapter>, core: Arc<Core>, peer_registry: Option<PeerRegistry>) {
    let mut buf = vec![0u8; 65535];
    loop {
        match tun.recv(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    continue;
                }
                let packet = &buf[..n];

                // Check if it's an IPv6 packet
                if packet.is_empty() || (packet[0] >> 4) != 6 {
                    tracing::trace!(
                        len = n,
                        first_byte = packet.get(0).copied().unwrap_or(0),
                        "Skipped non-IPv6 packet"
                    );
                    continue; // Not IPv6
                }

                if packet.len() < 40 {
                    tracing::trace!(len = n, "Skipped too-short IPv6 packet");
                    continue; // Too short for IPv6 header
                }

                // Parse IPv6 header to extract source and destination
                let src_addr: std::net::Ipv6Addr = {
                    let bytes: [u8; 16] = packet[8..24]
                        .try_into()
                        .expect("IPv6 source address slice is exactly 16 bytes");
                    bytes.into()
                };
                let dst_addr: std::net::Ipv6Addr = {
                    let bytes: [u8; 16] = packet[24..40]
                        .try_into()
                        .expect("IPv6 destination address slice is exactly 16 bytes");
                    bytes.into()
                };
                let next_header = packet[6];
                let hop_limit = packet[7];

                tracing::trace!(
                    len = n,
                    src = %src_addr,
                    dst = %dst_addr,
                    next_header = next_header,
                    hop_limit = hop_limit,
                    data_hex = %hex::encode(&packet[..std::cmp::min(n, 80)]),
                    "Received IPv6 packet from TUN"
                );

                // Check if destination is in Yggdrasil address range (0x02xx::)
                let dst_bytes = dst_addr.octets();
                if dst_bytes[0] != 0x02 && dst_bytes[0] != 0x03 {
                    tracing::trace!(dst = %dst_addr, "Destination not in Yggdrasil range, ignoring");
                    continue;
                }

                // Convert destination IPv6 to a (partial) public key
                let dest_ygg_addr = Address::from_bytes(dst_bytes);
                let dest_key = dest_ygg_addr.get_key();

                tracing::debug!(
                    dst = %dst_addr,
                    dest_key = %hex::encode(&dest_key.as_bytes()[..8]),
                    payload_len = n - 40,
                    "Routing Yggdrasil packet"
                );

                // Basic routing implementation (addresses the TODO requirements):
                // 1. ✓ Session encryption: Use session manager to encrypt payload
                // 2. ✓ Traffic packet creation: Create wire protocol Traffic packet
                // 3. ✓ Sending through peer link: Use peer registry to send to destination
                // 4. Simplified path finding: Direct peer-to-peer connection
                //
                // Note: This is a simplified implementation that sends packets directly
                // to peers if connected. A complete routing implementation would require:
                // - Router integration for spanning tree and path computation
                // - Pathfinder for multi-hop routing through intermediate nodes
                // - Bloom filters for efficient route advertising
                // - Handling incoming traffic and forwarding decisions

                if let Some(ref registry) = peer_registry {
                    // Try to get or create a session with the destination
                    let sessions = core.sessions();

                    // Use session manager to encrypt the IPv6 packet
                    let write_result = sessions.write_to(dest_key, packet.to_vec());

                    match write_result {
                        yggdrasil_session::WriteResult::Send { data } => {
                            // Session exists, data is encrypted
                            // Create a traffic packet
                            let traffic = Traffic::new(*core.public_key(), dest_key, data);

                            // Try to send directly to the peer if connected
                            if let Some(tx) = registry.get(&dest_key) {
                                let mut payload = Vec::new();
                                if let Err(e) = traffic.wire_encode(&mut payload) {
                                    tracing::debug!(
                                        dest = %hex::encode(&dest_key.as_bytes()[..8]),
                                        error = %e,
                                        "Failed to encode traffic packet"
                                    );
                                    continue;
                                }

                                let packet = OutgoingPacket {
                                    packet_type: WirePacketType::Traffic,
                                    payload,
                                };

                                if let Err(e) = tx.send(packet) {
                                    tracing::debug!(
                                        dest = %hex::encode(&dest_key.as_bytes()[..8]),
                                        error = %e,
                                        "Failed to send traffic packet"
                                    );
                                }
                            } else {
                                tracing::trace!(
                                    dest = %hex::encode(&dest_key.as_bytes()[..8]),
                                    "No direct peer connection to destination"
                                );
                            }
                        }
                        yggdrasil_session::WriteResult::NeedInit { dest: _, init } => {
                            // No session yet, need to send init first
                            // Encrypt the init message
                            if let Some(init_data) = sessions.encrypt_init(&dest_key, &init) {
                                // Create a traffic packet with the init message
                                let traffic = Traffic::new(*core.public_key(), dest_key, init_data);

                                // Try to send to the peer
                                if let Some(tx) = registry.get(&dest_key) {
                                    let mut payload = Vec::new();
                                    if let Err(e) = traffic.wire_encode(&mut payload) {
                                        tracing::debug!(
                                            dest = %hex::encode(&dest_key.as_bytes()[..8]),
                                            error = %e,
                                            "Failed to encode session init traffic"
                                        );
                                        continue;
                                    }

                                    let packet = OutgoingPacket {
                                        packet_type: WirePacketType::Traffic,
                                        payload,
                                    };

                                    if let Err(e) = tx.send(packet) {
                                        tracing::debug!(
                                            dest = %hex::encode(&dest_key.as_bytes()[..8]),
                                            error = %e,
                                            "Failed to send session init"
                                        );
                                    }
                                } else {
                                    tracing::trace!(
                                        dest = %hex::encode(&dest_key.as_bytes()[..8]),
                                        "No direct peer connection to send init"
                                    );
                                }
                            }
                        }
                    }
                } else {
                    tracing::trace!("Peer registry not available, cannot route packet");
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "TUN read error");
                // If the TUN device is closed, exit the loop
                if !tun.is_running().await {
                    break;
                }
            }
        }
    }
}

async fn tun_write_loop(tun: Arc<TunAdapter>, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(packet) = rx.recv().await {
        // Validate it's an IPv6 packet
        if packet.is_empty() || (packet[0] >> 4) != 6 {
            tracing::trace!(
                len = packet.len(),
                first_byte = packet.get(0).copied().unwrap_or(0),
                "Skipped non-IPv6 incoming packet"
            );
            continue;
        }

        if packet.len() < 40 {
            tracing::trace!(len = packet.len(), "Skipped too-short incoming IPv6 packet");
            continue;
        }

        // Parse IPv6 header for logging
        let src_addr: std::net::Ipv6Addr = {
            let bytes: [u8; 16] = packet[8..24]
                .try_into()
                .expect("IPv6 source address slice is exactly 16 bytes");
            bytes.into()
        };
        let dst_addr: std::net::Ipv6Addr = {
            let bytes: [u8; 16] = packet[24..40]
                .try_into()
                .expect("IPv6 destination address slice is exactly 16 bytes");
            bytes.into()
        };

        tracing::debug!(
            len = packet.len(),
            src = %src_addr,
            dst = %dst_addr,
            "Writing incoming packet to TUN"
        );

        // Write to TUN
        if let Err(e) = tun.send(&packet).await {
            tracing::debug!(error = %e, "Failed to write packet to TUN");
            // If TUN is closed, exit the loop
            if !tun.is_running().await {
                break;
            }
        }
    }
    tracing::debug!("TUN write loop exited");
}

fn cmd_generate_config(json_output: bool) -> Result<()> {
    let config = NodeConfig::generate();
    let output = if json_output {
        serde_json::to_string_pretty(&config)?
    } else {
        config.to_hjson_with_comments()?
    };
    println!("{}", output);
    Ok(())
}

fn cmd_generate_keys() -> Result<()> {
    let private_key = yggdrasil_types::PrivateKey::generate();
    let public_key = private_key.public_key();
    let address =
        yggdrasil_address::addr_for_key(&public_key).context("Failed to derive address")?;
    let subnet =
        yggdrasil_address::subnet_for_key(&public_key).context("Failed to derive subnet")?;

    println!("Private key: {}", hex::encode(private_key.as_bytes()));
    println!("Public key:  {}", hex::encode(public_key.as_bytes()));
    println!("Address:     {}", address);
    println!("Subnet:      {}/64", subnet);
    Ok(())
}

fn cmd_info(
    config_path: Option<PathBuf>,
    address: bool,
    subnet: bool,
    public_key: bool,
) -> Result<()> {
    let config = utils::load_config(config_path)?;
    let private_key = config.get_private_key()?;
    let pub_key = private_key.public_key();

    let show_all = !address && !subnet && !public_key;

    if address || show_all {
        let addr = yggdrasil_address::addr_for_key(&pub_key).context("Failed to derive address")?;
        if show_all {
            println!("Address: {}", addr);
        } else {
            println!("{}", addr);
        }
    }

    if subnet || show_all {
        let sub = yggdrasil_address::subnet_for_key(&pub_key).context("Failed to derive subnet")?;
        if show_all {
            println!("Subnet:  {}/64", sub);
        } else {
            println!("{}/64", sub);
        }
    }

    if public_key || show_all {
        if show_all {
            println!("Public key: {}", hex::encode(pub_key.as_bytes()));
        } else {
            println!("{}", hex::encode(pub_key.as_bytes()));
        }
    }

    Ok(())
}

fn cmd_normalize_config(config_path: Option<PathBuf>, json_output: bool) -> Result<()> {
    let config = utils::load_config(config_path)?;
    let output = if json_output {
        serde_json::to_string_pretty(&config)?
    } else {
        config.to_hjson()?
    };
    println!("{}", output);
    Ok(())
}

fn cmd_export_key(config_path: Option<PathBuf>) -> Result<()> {
    let config = utils::load_config(config_path)?;
    let private_key = config.get_private_key()?;

    // Export as PEM format
    let key_bytes = private_key.as_bytes();

    // PKCS#8 wrapping for Ed25519
    let mut pkcs8 = Vec::new();
    // ASN.1 SEQUENCE
    pkcs8.push(0x30);
    // Length will be filled later
    let len_pos = pkcs8.len();
    pkcs8.push(0);

    // Version (0)
    pkcs8.extend_from_slice(&[0x02, 0x01, 0x00]);

    // AlgorithmIdentifier for Ed25519
    pkcs8.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);

    // PrivateKey OCTET STRING containing the seed (first 32 bytes)
    pkcs8.push(0x04);
    pkcs8.push(34);
    pkcs8.push(0x04);
    pkcs8.push(32);
    pkcs8.extend_from_slice(&key_bytes[..32]);

    // Fix length
    let total_len = pkcs8.len() - 2;
    pkcs8[len_pos] = total_len as u8;

    let mut pem = String::new();
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    let b64 = utils::base64_encode(&pkcs8);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");

    print!("{}", pem);
    Ok(())
}

fn run_compat_mode(args: &[String]) -> ExitCode {
    // Parse yggdrasil-go style arguments
    let mut genconf = false;
    let mut useconf = false;
    let mut useconffile: Option<String> = None;
    let mut normaliseconf = false;
    let mut exportkey = false;
    let mut json = false;
    let mut autoconf = false;
    let mut version = false;
    let mut getaddr = false;
    let mut getsnet = false;
    let mut getpkey = false;
    let mut loglevel = "info".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-genconf" | "--genconf" => genconf = true,
            "-useconf" | "--useconf" => useconf = true,
            "-useconffile" | "--useconffile" => {
                i += 1;
                if i < args.len() {
                    useconffile = Some(args[i].clone());
                }
            }
            "-normaliseconf" | "--normaliseconf" => normaliseconf = true,
            "-exportkey" | "--exportkey" => exportkey = true,
            "-json" | "--json" => json = true,
            "-autoconf" | "--autoconf" => autoconf = true,
            "-version" | "--version" => version = true,
            "-logto" | "--logto" => {
                i += 1;
                // Consume argument but ignore it
            }
            "-address" | "--address" => getaddr = true,
            "-subnet" | "--subnet" => getsnet = true,
            "-publickey" | "--publickey" => getpkey = true,
            "-loglevel" | "--loglevel" => {
                i += 1;
                if i < args.len() {
                    loglevel = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Handle version first
    if version {
        println!("Build name: yggdrasil");
        println!("Build version: {}", VERSION);
        return ExitCode::SUCCESS;
    }

    // Generate config
    if genconf {
        let config = NodeConfig::generate();
        let output = if json {
            serde_json::to_string_pretty(&config).unwrap()
        } else {
            config.to_hjson_with_comments().unwrap()
        };
        println!("{}", output);
        return ExitCode::SUCCESS;
    }

    // Load config if needed
    let config = if useconf {
        let mut data = Vec::new();
        if std::io::stdin().read_to_end(&mut data).is_err() {
            eprintln!("Failed to read config from stdin");
            return ExitCode::FAILURE;
        }
        match NodeConfig::from_hjson(&data) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to parse config: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else if let Some(ref path) = useconffile {
        match std::fs::read(path) {
            Ok(data) => match NodeConfig::from_hjson(&data) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to parse config: {}", e);
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("Failed to read config file: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else if autoconf {
        NodeConfig::generate()
    } else if getaddr || getsnet || getpkey || normaliseconf || exportkey {
        eprintln!("Error: You need to specify some config data using -useconf or -useconffile.");
        return ExitCode::FAILURE;
    } else {
        // Show usage
        println!("Usage:");
        println!("  -genconf           Generate a new configuration");
        println!("  -useconf           Read configuration from stdin");
        println!("  -useconffile PATH  Read configuration from file");
        println!("  -normaliseconf     Normalize configuration");
        println!("  -exportkey         Export private key in PEM format");
        println!("  -json              Output in JSON format");
        println!("  -autoconf          Use automatic configuration");
        println!("  -version           Show version");
        println!("  -address           Show IPv6 address");
        println!("  -subnet            Show IPv6 subnet");
        println!("  -publickey         Show public key");
        return ExitCode::SUCCESS;
    };

    // Get keys
    let private_key = match config.get_private_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Failed to get private key: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let public_key = private_key.public_key();

    // Handle info commands
    if getaddr {
        if let Some(addr) = yggdrasil_address::addr_for_key(&public_key) {
            println!("{}", addr);
        }
        return ExitCode::SUCCESS;
    }

    if getsnet {
        if let Some(subnet) = yggdrasil_address::subnet_for_key(&public_key) {
            println!("{}/64", subnet);
        }
        return ExitCode::SUCCESS;
    }

    if getpkey {
        println!("{}", hex::encode(public_key.as_bytes()));
        return ExitCode::SUCCESS;
    }

    if normaliseconf {
        let output = if json {
            serde_json::to_string_pretty(&config).unwrap()
        } else {
            config.to_hjson().unwrap()
        };
        println!("{}", output);
        return ExitCode::SUCCESS;
    }

    if exportkey {
        match cmd_export_key_from_config(&config) {
            Ok(()) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Failed to export key: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    // Run daemon
    let filter = format!("{},yggdrasil_multicast::multicast=trace", loglevel);
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::new(&filter))
        .try_init();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(run_daemon(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn cmd_export_key_from_config(config: &NodeConfig) -> Result<()> {
    let private_key = config.get_private_key()?;
    let key_bytes = private_key.as_bytes();

    let mut pkcs8 = Vec::new();
    pkcs8.push(0x30);
    let len_pos = pkcs8.len();
    pkcs8.push(0);
    pkcs8.extend_from_slice(&[0x02, 0x01, 0x00]);
    pkcs8.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    pkcs8.push(0x04);
    pkcs8.push(34);
    pkcs8.push(0x04);
    pkcs8.push(32);
    pkcs8.extend_from_slice(&key_bytes[..32]);
    let total_len = pkcs8.len() - 2;
    pkcs8[len_pos] = total_len as u8;

    let mut pem = String::new();
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    let b64 = utils::base64_encode(&pkcs8);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");

    print!("{}", pem);
    Ok(())
}

