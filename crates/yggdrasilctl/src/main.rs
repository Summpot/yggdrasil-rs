#![forbid(unsafe_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use yggdrasil_core::{admin_compat, AdminClient};

#[derive(Parser)]
#[command(name = "yggdrasilctl")]
#[command(about = "Yggdrasil control utility", long_about = None)]
struct Cli {
    /// Admin socket path
    #[arg(short, long, default_value = "/var/run/yggdrasil.sock")]
    endpoint: String,

    /// Output in JSON format
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Get information about this node
    #[command(name = "get-self")]
    GetSelf,
    /// List all peers
    #[command(name = "get-peers")]
    GetPeers,
    /// Get DHT information
    #[command(name = "get-dht")]
    GetDHT,
    /// Get routing table
    #[command(name = "get-paths")]
    GetPaths,
    /// Get sessions
    #[command(name = "get-sessions")]
    GetSessions,
    /// Add a peer
    #[command(name = "add-peer")]
    AddPeer {
        /// Peer URI (e.g., tcp://host:port)
        uri: String,
        /// Interface to use (optional)
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Remove a peer
    #[command(name = "remove-peer")]
    RemovePeer {
        /// Peer URI
        uri: String,
        /// Interface to use (optional)
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Get multicast interfaces
    #[command(name = "get-multicast")]
    GetMulticastInterfaces,
    /// Get TUN/TAP information
    #[command(name = "get-tun")]
    GetTUN,
    /// List available commands
    List,
    /// Compatibility mode for original yggdrasilctl
    Compat {
        /// Command to execute in compatibility mode
        #[arg(value_name = "COMMAND")]
        command: String,

        /// Output in Go-compatible format (PascalCase field names)
        #[arg(long)]
        go_compat: bool,

        /// Additional arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = AdminClient::new(&cli.endpoint);
    let json_output = cli.json;

    match cli.command {
        Some(Commands::GetSelf) => get_self(&client, json_output).await,
        Some(Commands::GetPeers) => get_peers(&client, json_output).await,
        Some(Commands::GetDHT) => get_dht(&client, json_output).await,
        Some(Commands::GetPaths) => get_paths(&client, json_output).await,
        Some(Commands::GetSessions) => get_sessions(&client, json_output).await,
        Some(Commands::AddPeer { uri, interface }) => {
            add_peer(&client, &uri, interface.as_deref(), json_output).await
        }
        Some(Commands::RemovePeer { uri, interface }) => {
            remove_peer(&client, &uri, interface.as_deref(), json_output).await
        }
        Some(Commands::GetMulticastInterfaces) => {
            get_multicast_interfaces(&client, json_output).await
        }
        Some(Commands::GetTUN) => get_tun(&client, json_output).await,
        Some(Commands::List) => list_commands(&client, json_output).await,
        Some(Commands::Compat { command, args, go_compat }) => {
            compat_command(&client, &command, &args, cli.endpoint.clone(), go_compat).await
        }
        None => {
            eprintln!("No command specified. Use --help for usage information.");
            eprintln!("Available commands: get-self, get-peers, get-paths, get-sessions, add-peer, remove-peer, list");
            std::process::exit(1);
        }
    }
}

async fn get_self(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_self().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("Node Information:");
        println!("  Build Name:       {}", response.build_name);
        println!("  Build Version:    {}", response.build_version);
        println!("  Public Key:       {}", response.public_key);
        println!("  IPv6 Address:     {}", response.ip_address);
        println!("  IPv6 Subnet:      {}", response.subnet);
        println!("  Routing Entries:  {}", response.routing_entries);
    }

    Ok(())
}

async fn get_peers(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_peers().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    if response.peers.is_empty() {
        println!("No peers connected");
        return Ok(());
    }

    println!("Connected Peers ({}):", response.peers.len());
    println!();

    for (i, peer) in response.peers.iter().enumerate() {
        println!("Peer #{}:", i + 1);
        println!("  Public Key:   {}", peer.public_key);
        if let Some(addr) = &peer.ip_address {
            println!("  IPv6 Address: {}", addr);
        }
        if let Some(uri) = &peer.uri {
            println!("  URI:          {}", uri);
        }
        println!(
            "  Direction:    {}",
            if peer.inbound { "Inbound" } else { "Outbound" }
        );
        println!("  Status:       {}", if peer.up { "Up" } else { "Down" });
        println!("  Port:         {}", peer.port);
        println!("  Priority:     {}", peer.priority);
        println!("  Cost:         {}", peer.cost);

        if let Some(uptime) = peer.uptime {
            println!("  Uptime:       {:.2}s", uptime);
        }
        if let Some(rx) = peer.rx_bytes {
            println!("  RX Bytes:     {}", format_bytes(rx));
        }
        if let Some(tx) = peer.tx_bytes {
            println!("  TX Bytes:     {}", format_bytes(tx));
        }
        if let Some(rx_rate) = peer.rx_rate {
            println!("  RX Rate:      {}/s", format_bytes(rx_rate));
        }
        if let Some(tx_rate) = peer.tx_rate {
            println!("  TX Rate:      {}/s", format_bytes(tx_rate));
        }
        if let Some(latency) = peer.latency {
            println!("  Latency:      {}ms", latency / 1_000_000);
        }
        if let Some(err) = &peer.last_error {
            println!("  Last Error:   {}", err);
        }
        println!();
    }

    Ok(())
}

async fn get_dht(_client: &AdminClient, json: bool) -> Result<()> {
    if json {
        println!("{{}}");
    } else {
        println!("DHT information not yet supported");
        println!("This will show DHT routing table entries");
    }
    Ok(())
}

async fn get_paths(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_paths().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    if response.paths.is_empty() {
        println!("No paths found");
        return Ok(());
    }

    println!("Routing Paths ({}):", response.paths.len());
    println!();

    for (i, path) in response.paths.iter().enumerate() {
        println!("Path #{}:", i + 1);
        println!("  Public Key:   {}", path.public_key);
        println!("  IPv6 Address: {}", path.ip_address);
        println!("  Path:         {:?}", path.path);
        println!();
    }

    Ok(())
}

async fn get_sessions(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_sessions().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    if response.sessions.is_empty() {
        println!("No active sessions");
        return Ok(());
    }

    println!("Active Sessions ({}):", response.sessions.len());
    println!();

    for (i, session) in response.sessions.iter().enumerate() {
        println!("Session #{}:", i + 1);
        println!("  Public Key:   {}", session.public_key);
        println!("  IPv6 Address: {}", session.ip_address);
        println!("  RX Bytes:     {}", format_bytes(session.rx_bytes));
        println!("  TX Bytes:     {}", format_bytes(session.tx_bytes));
        println!("  Uptime:       {:.2}s", session.uptime);
        println!();
    }

    Ok(())
}

async fn add_peer(
    client: &AdminClient,
    uri: &str,
    interface: Option<&str>,
    json: bool,
) -> Result<()> {
    let response = client.add_peer(uri, interface).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    println!("Adding peer: {}", uri);
    if let Some(iface) = interface {
        println!("Using interface: {}", iface);
    }

    if response.success.unwrap_or(false) {
        println!("✓ Peer added successfully");
    } else if let Some(err) = response.error {
        println!("✗ Failed to add peer: {}", err);
    } else {
        println!("✓ Peer add request completed");
    }

    Ok(())
}

async fn remove_peer(
    client: &AdminClient,
    uri: &str,
    interface: Option<&str>,
    json: bool,
) -> Result<()> {
    let response = client.remove_peer(uri, interface).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    println!("Removing peer: {}", uri);
    if let Some(iface) = interface {
        println!("Using interface: {}", iface);
    }

    if response.success.unwrap_or(false) {
        println!("✓ Peer removed successfully");
    } else if let Some(err) = response.error {
        println!("✗ Failed to remove peer: {}", err);
    } else {
        println!("✓ Peer remove request completed");
    }

    Ok(())
}

async fn get_multicast_interfaces(_client: &AdminClient, json: bool) -> Result<()> {
    if json {
        println!("{{}}");
    } else {
        println!("Multicast interfaces not yet supported");
        println!("This will show active multicast discovery interfaces");
    }
    Ok(())
}

async fn get_tun(_client: &AdminClient, json: bool) -> Result<()> {
    if json {
        println!("{{}}");
    } else {
        println!("TUN information not yet supported");
        println!("This will show TUN/TAP device configuration");
    }
    Ok(())
}

async fn list_commands(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.list().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    println!("Available Commands:");
    println!();

    for entry in response.list {
        println!("  {}", entry.command);
        println!("    {}", entry.description);
        if !entry.fields.is_empty() {
            println!("    Fields: {}", entry.fields.join(", "));
        }
        println!();
    }

    Ok(())
}

/// Compatibility mode for original yggdrasilctl command format
async fn compat_command(
    client: &AdminClient,
    command: &str,
    args: &[String],
    _endpoint: String,
    go_compat: bool,
) -> Result<()> {
    // Parse JSON flag from args
    let json = args.contains(&"--json".to_string()) || args.contains(&"-json".to_string());

    // Parse key=value style arguments (Go style)
    let mut parsed_args = std::collections::HashMap::new();
    for arg in args {
        if arg.starts_with("--") || arg.starts_with("-") {
            continue;
        }
        if let Some((key, value)) = arg.split_once('=') {
            parsed_args.insert(key.to_string(), value.to_string());
        }
    }

    // Map original command names to new functions
    match command {
        "getSelf" | "getself" => {
            if go_compat {
                get_self_go_compat(client, json).await
            } else {
                get_self(client, json).await
            }
        }
        "getPeers" | "getpeers" => {
            if go_compat {
                get_peers_go_compat(client, json).await
            } else {
                get_peers(client, json).await
            }
        }
        "getDHT" | "getdht" => get_dht(client, json).await,
        "getPaths" | "getpaths" => {
            if go_compat {
                get_paths_go_compat(client, json).await
            } else {
                get_paths(client, json).await
            }
        }
        "getSessions" | "getsessions" => {
            if go_compat {
                get_sessions_go_compat(client, json).await
            } else {
                get_sessions(client, json).await
            }
        }
        "getMulticast" | "getmulticast" => get_multicast_interfaces(client, json).await,
        "getTUN" | "gettun" => get_tun(client, json).await,
        "list" => list_commands(client, json).await,
        "addPeer" | "addpeer" => {
            // Support both positional and key=value style
            let uri = parsed_args
                .get("uri")
                .map(|s| s.as_str())
                .or_else(|| args.first().map(|s| s.as_str()))
                .ok_or_else(|| anyhow::anyhow!("addPeer requires URI argument"))?;

            let interface = parsed_args
                .get("interface")
                .map(|s| s.as_str())
                .or_else(|| {
                    args.iter()
                        .position(|a| a == "--interface" || a == "-i")
                        .and_then(|i| args.get(i + 1))
                        .map(|s| s.as_str())
                });

            add_peer(client, uri, interface, json).await
        }
        "removePeer" | "removepeer" => {
            // Support both positional and key=value style
            let uri = parsed_args
                .get("uri")
                .map(|s| s.as_str())
                .or_else(|| args.first().map(|s| s.as_str()))
                .ok_or_else(|| anyhow::anyhow!("removePeer requires URI argument"))?;

            let interface = parsed_args
                .get("interface")
                .map(|s| s.as_str())
                .or_else(|| {
                    args.iter()
                        .position(|a| a == "--interface" || a == "-i")
                        .and_then(|i| args.get(i + 1))
                        .map(|s| s.as_str())
                });

            remove_peer(client, uri, interface, json).await
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Use 'list' to see available commands");
            std::process::exit(1);
        }
    }
}

/// Format bytes with appropriate unit
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1}TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

// Go-compatible output functions

async fn get_self_go_compat(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_self().await?;
    let go_response: admin_compat::GetSelfResponseGo = response.into();

    if json {
        println!("{}", serde_json::to_string_pretty(&go_response)?);
    } else {
        println!("Node Information:");
        println!("  Build Name:       {}", go_response.build_name);
        println!("  Build Version:    {}", go_response.build_version);
        println!("  Public Key:       {}", go_response.public_key);
        println!("  IPv6 Address:     {}", go_response.address);
        println!("  IPv6 Subnet:      {}", go_response.subnet);
        println!("  Routing Entries:  {}", go_response.routing_entries);
    }

    Ok(())
}

async fn get_peers_go_compat(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_peers().await?;
    let go_response: admin_compat::GetPeersResponseGo = response.into();

    if json {
        println!("{}", serde_json::to_string_pretty(&go_response)?);
        return Ok(());
    }

    if go_response.peers.is_empty() {
        println!("No peers connected");
        return Ok(());
    }

    println!("Connected Peers ({}):", go_response.peers.len());
    println!();

    for (i, peer) in go_response.peers.iter().enumerate() {
        println!("Peer #{}:", i + 1);
        println!("  Public Key:   {}", peer.public_key);
        if let Some(addr) = &peer.address {
            println!("  IPv6 Address: {}", addr);
        }
        if let Some(uri) = &peer.uri {
            println!("  URI:          {}", uri);
        }
        println!(
            "  Direction:    {}",
            if peer.inbound { "Inbound" } else { "Outbound" }
        );
        println!("  Status:       {}", if peer.up { "Up" } else { "Down" });
        println!("  Port:         {}", peer.port);
        println!("  Priority:     {}", peer.priority);
        if let Some(cost) = peer.cost {
            println!("  Cost:         {}", cost);
        }

        if let Some(uptime) = peer.uptime {
            println!("  Uptime:       {:.2}s", uptime);
        }
        if let Some(rx) = peer.rx_bytes {
            println!("  RX Bytes:     {}", format_bytes(rx));
        }
        if let Some(tx) = peer.tx_bytes {
            println!("  TX Bytes:     {}", format_bytes(tx));
        }
        if let Some(latency) = peer.latency {
            println!("  Latency:      {}ms", latency / 1_000_000);
        }
        if let Some(coords) = &peer.coords {
            println!("  Coords:       {:?}", coords);
        }
        if let Some(root) = &peer.root {
            println!("  Root:         {}", root);
        }
        println!();
    }

    Ok(())
}

async fn get_paths_go_compat(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_paths().await?;
    let go_response: admin_compat::GetPathsResponseGo = response.into();

    if json {
        println!("{}", serde_json::to_string_pretty(&go_response)?);
        return Ok(());
    }

    if go_response.paths.is_empty() {
        println!("No paths found");
        return Ok(());
    }

    println!("Routing Paths ({}):", go_response.paths.len());
    println!();

    for (i, path) in go_response.paths.iter().enumerate() {
        println!("Path #{}:", i + 1);
        println!("  Public Key:   {}", path.public_key);
        println!("  IPv6 Address: {}", path.address);
        println!("  Path:         {:?}", path.path);
        println!();
    }

    Ok(())
}

async fn get_sessions_go_compat(client: &AdminClient, json: bool) -> Result<()> {
    let response = client.get_sessions().await?;
    let go_response: admin_compat::GetSessionsResponseGo = response.into();

    if json {
        println!("{}", serde_json::to_string_pretty(&go_response)?);
        return Ok(());
    }

    if go_response.sessions.is_empty() {
        println!("No active sessions");
        return Ok(());
    }

    println!("Active Sessions ({}):", go_response.sessions.len());
    println!();

    for (i, session) in go_response.sessions.iter().enumerate() {
        println!("Session #{}:", i + 1);
        println!("  Public Key:   {}", session.public_key);
        println!("  IPv6 Address: {}", session.address);
        println!("  RX Bytes:     {}", format_bytes(session.rx_bytes));
        println!("  TX Bytes:     {}", format_bytes(session.tx_bytes));
        println!("  Uptime:       {:.2}s", session.uptime);
        if let Some(coords) = &session.coords {
            println!("  Coords:       {:?}", coords);
        }
        if let Some(root) = &session.root {
            println!("  Root:         {}", root);
        }
        println!();
    }

    Ok(())
}
