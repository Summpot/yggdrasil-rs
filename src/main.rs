//! Yggdrasil network daemon.
//!
//! A modern CLI for the Yggdrasil mesh networking daemon.
//! Supports both legacy yggdrasil-go compatible mode and modern subcommand-based usage.

mod admin_commands;
mod cli;
mod debug_logger;
mod routing;
mod service;
mod utils;

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::Layer;

use anyhow::{Context, Result};
use clap::Parser;
use debug_logger::PlaintextDebugLogger;
use tokio::sync::{broadcast, mpsc};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use yggdrasil::{AdminServer, Core, NodeConfig, VERSION};
use yggdrasil_config::get_defaults;
use yggdrasil_link::{LinkType, Links, LinksListenerFactory};
use yggdrasil_multicast::{
    Multicast, MulticastConfig, MulticastInterfaceConfig as MulticastIfaceConfig,
};
use yggdrasil_tun::{TunAdapter, TunConfig};

use cli::{Cli, Commands};
use routing::{PeerRegistry, RoutingRuntime};

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
    let default_console_filter = format!("{},yggdrasil_multicast::multicast=error", cli.log_level);
    let console_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&default_console_filter));

    // Create console layer with its filter
    let console_layer = tracing_subscriber::fmt::layer().with_filter(console_filter);

    // Optionally create file layer with trace-level filter
    if let Some(log_file) = &cli.log_file {
        // Use RollingFileAppender for better log management
        let file_dir = log_file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("logs"));
        let file_name = log_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("yggdrasil.log");

        let file_appender = tracing_appender::rolling::never(file_dir, file_name);

        // File layer always uses trace level, but also respects RUST_LOG if set
        let file_filter =
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // Default file filter: trace for everything
                tracing_subscriber::EnvFilter::new(
                    "trace,yggdrasil_multicast::multicast=warn,yggdrasil_link::peer_handler=warn",
                )
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
        tracing_subscriber::registry().with(console_layer).init();
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
    let debug_plaintext_log = cli.debug_plaintext_log.clone();
    match cli.command {
        Some(Commands::Run {
            config,
            stdin,
            admin_listen,
            if_name,
            if_mtu,
            autoconf,
        }) => cmd_run(
            config,
            stdin,
            admin_listen,
            if_name,
            if_mtu,
            autoconf,
            debug_plaintext_log,
        ),
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
    debug_plaintext_log: Option<PathBuf>,
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
    rt.block_on(async { run_daemon(config, debug_plaintext_log).await })
}

async fn run_daemon(
    config: NodeConfig,
    debug_plaintext_log: Option<PathBuf>,
) -> Result<()> {
    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Get platform defaults for values not specified in config
    let defaults = get_defaults();

    // Configure optional plaintext debug logging
    let debug_logger = if let Some(path) = debug_plaintext_log {
        let logger = PlaintextDebugLogger::from_path(path)
            .with_context(|| "Failed to open plaintext debug log")?;
        tracing::info!(path = %logger.path().display(), "Plaintext debug logging enabled");
        Some(Arc::new(logger))
    } else {
        None
    };

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

    // Create routing runtime
    let routing = Arc::new(RoutingRuntime::new(
        Arc::clone(&core),
        debug_logger.clone(),
    ));

    // Start links manager
    let links_result = start_links(&config, Arc::clone(&routing)).await?;
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
    let tun_adapter = start_tun_adapter(
        &config,
        &core,
        Arc::clone(&routing),
        admin_server.as_ref(),
        peer_registry,
        incoming_rx,
    )
    .await?;

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
    routing: Arc<RoutingRuntime>,
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
    let peer_registry: PeerRegistry = Arc::new(dashmap::DashMap::new());
    let peer_registry_clone = Arc::clone(&peer_registry);
    let routing_for_peers = Arc::clone(&routing);
    let links_for_events = Arc::clone(&links);

    // Periodic routing maintenance
    let routing_for_tick = Arc::clone(&routing);
    let registry_for_tick = Arc::clone(&peer_registry);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            routing_for_tick.maintenance_tick(&registry_for_tick);
        }
    });

    // Create channel for incoming decrypted packets to be written to TUN
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Clone routing for the peer event handler
    let routing_clone = Arc::clone(&routing_for_peers);

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

            // Inform routing about the new peer so announcements and requests can be sent
            routing_for_peers.register_peer(
                event.public_key,
                event.peer_port,
                event.priority,
                &peer_registry_clone,
            );

            // Spawn a task to handle events from this peer
            let _peer_key = event.public_key;
            let peer_registry_inner = Arc::clone(&peer_registry_clone);
            let routing_for_peer = Arc::clone(&routing_clone);
            let incoming_tx_for_peer = incoming_tx.clone();
            let links_for_peer = Arc::clone(&links_for_events);
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
                            links_for_peer.update_rtt(&from, res.port, rtt);
                            routing_for_peer.handle_sig_response(
                                from,
                                res,
                                rtt,
                                &peer_registry_inner,
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
                            routing_for_peer.handle_announce(from, announce, &peer_registry_inner);
                        }
                        yggdrasil_link::PeerEvent::Traffic { from, traffic } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                source = %hex::encode(&traffic.source.as_bytes()[..8]),
                                dest = %hex::encode(&traffic.dest.as_bytes()[..8]),
                                payload_len = traffic.payload.len(),
                                "Received traffic"
                            );
                            routing_for_peer.handle_incoming_traffic(
                                from,
                                traffic,
                                &peer_registry_inner,
                                &incoming_tx_for_peer,
                            );
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
                            routing_for_peer.handle_path_lookup(from, lookup, &peer_registry_inner);
                        }
                        yggdrasil_link::PeerEvent::PathNotify { from, notify } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                source = %hex::encode(&notify.source.as_bytes()[..8]),
                                dest = %hex::encode(&notify.dest.as_bytes()[..8]),
                                "Received path notify"
                            );
                            routing_for_peer.forward_path_notify(notify, &peer_registry_inner);
                        }
                        yggdrasil_link::PeerEvent::PathBroken { from, broken } => {
                            tracing::trace!(
                                from = %hex::encode(&from.as_bytes()[..8]),
                                source = %hex::encode(&broken.source.as_bytes()[..8]),
                                dest = %hex::encode(&broken.dest.as_bytes()[..8]),
                                "Received path broken"
                            );
                            routing_for_peer.forward_path_broken(broken, &peer_registry_inner);
                        }
                        yggdrasil_link::PeerEvent::Disconnected { key, peer_port, error } => {
                            tracing::info!(
                                peer = %hex::encode(&key.as_bytes()[..8]),
                                error = ?error,
                                "Peer disconnected"
                            );
                            // Remove peer from registry
                            peer_registry_inner.remove(&key);
                            routing_for_peer.peer_disconnected(&key, &peer_registry_inner);
                            links_for_peer.cleanup_connection(&key, peer_port, error.clone());
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
            // Connect to the discovered peer
            if let Some(ref links) = links_clone {
                if links.has_active_connection(&event.public_key) {
                    tracing::trace!(
                        peer = %hex::encode(&event.public_key.as_bytes()[..8]),
                        addr = %event.addr,
                        "Skipping multicast connect, link already active"
                    );
                    continue;
                }

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
    routing: Arc<RoutingRuntime>,
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
            let routing_clone = Arc::clone(&routing);
            tokio::spawn(async move {
                tun_read_loop(tun_clone, routing_clone, peer_registry).await;
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

async fn tun_read_loop(
    tun: Arc<TunAdapter>,
    routing: Arc<RoutingRuntime>,
    peer_registry: Option<PeerRegistry>,
) {
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

                if let Some(ref registry) = peer_registry {
                    routing.handle_outgoing_ipv6_packet(packet, registry);
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

    match rt.block_on(run_daemon(config, None)) {
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
