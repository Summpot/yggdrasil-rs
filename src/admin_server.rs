//! Admin socket server for the Yggdrasil daemon.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use yggdrasil_link::{LinkType, Links};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::Core;
use crate::VERSION;

/// Admin server errors.
#[derive(Debug, Error)]
pub enum AdminServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("handler already exists: {0}")]
    HandlerExists(String),
    #[error("already started")]
    AlreadyStarted,
    #[error("not started")]
    NotStarted,
}

/// Admin socket request format.
#[derive(Debug, Deserialize)]
pub struct AdminRequest {
    #[serde(alias = "name", alias = "request")]
    pub name: String,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    #[serde(default)]
    pub keepalive: bool,
}

/// Admin socket response format.
#[derive(Debug, Serialize)]
pub struct AdminResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub request: AdminRequestEcho,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AdminRequestEcho {
    pub request: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
}

/// Handler function type.
pub type HandlerFn = Box<
    dyn Fn(Option<serde_json::Value>, &AdminContext) -> Result<serde_json::Value, String>
        + Send
        + Sync,
>;

/// Handler metadata.
struct Handler {
    description: String,
    args: Vec<String>,
    handler: HandlerFn,
}

/// Context passed to handlers.
pub struct AdminContext {
    pub core: Arc<Core>,
    pub links: Option<Arc<Links>>,
    pub tun_name: Option<String>,
    pub tun_mtu: Option<u64>,
    pub tun_enabled: bool,
}

/// Admin socket server.
pub struct AdminServer {
    listen_addr: String,
    handlers: RwLock<HashMap<String, Handler>>,
    context: Arc<RwLock<AdminContext>>,
    shutdown_tx: broadcast::Sender<()>,
    running: RwLock<bool>,
}

impl AdminServer {
    /// Create a new admin server.
    pub fn new(listen_addr: &str, core: Arc<Core>) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            listen_addr: listen_addr.to_string(),
            handlers: RwLock::new(HashMap::new()),
            context: Arc::new(RwLock::new(AdminContext {
                core,
                links: None,
                tun_name: None,
                tun_mtu: None,
                tun_enabled: false,
            })),
            shutdown_tx,
            running: RwLock::new(false),
        }
    }

    /// Set the links reference.
    pub fn set_links(&self, links: Arc<Links>) {
        self.context.write().links = Some(links);
    }

    /// Set TUN interface information.
    pub fn set_tun_info(&self, name: Option<String>, mtu: Option<u64>, enabled: bool) {
        let mut ctx = self.context.write();
        ctx.tun_name = name;
        ctx.tun_mtu = mtu;
        ctx.tun_enabled = enabled;
    }

    /// Add a handler.
    pub fn add_handler<F>(&self, name: &str, description: &str, args: Vec<&str>, handler: F)
    where
        F: Fn(Option<serde_json::Value>, &AdminContext) -> Result<serde_json::Value, String>
            + Send
            + Sync
            + 'static,
    {
        let mut handlers = self.handlers.write();
        handlers.insert(
            name.to_lowercase(),
            Handler {
                description: description.to_string(),
                args: args.into_iter().map(|s| s.to_string()).collect(),
                handler: Box::new(handler),
            },
        );
    }

    /// Setup default admin handlers.
    pub fn setup_handlers(&self) {
        // list - List available commands
        self.add_handler("list", "List available commands", vec![], |_, _| {
            // This is handled specially in handle_request
            Ok(serde_json::json!({}))
        });

        // getSelf - Get self info
        self.add_handler(
            "getSelf",
            "Show details about this node",
            vec![],
            |_, ctx| {
                let core = &ctx.core;
                Ok(serde_json::json!({
                    "buildName": "yggdrasil",
                    "buildVersion": VERSION,
                    "publicKey": hex::encode(core.public_key().as_bytes()),
                    "ipAddress": core.address().to_string(),
                    "subnet": format!("{}/64", core.subnet()),
                    "routingEntries": ctx.links.as_ref().map(|l| l.connection_count() as u64).unwrap_or(0),
                }))
            },
        );

        // getPeers - Get connected peers
        self.add_handler(
            "getPeers",
            "Show directly connected peers",
            vec!["sort"],
            |_, ctx| {
                let peers: Vec<serde_json::Value> = if let Some(links) = &ctx.links {
                    links
                        .get_links()
                        .into_iter()
                        .map(|link| {
                            let uptime = link.info.established.elapsed().as_secs_f64();
                            let last_error_time = link
                                .info
                                .last_error_time
                                .map(|t| t.elapsed().as_secs_f64())
                                .unwrap_or(0.0);

                            serde_json::json!({
                                "URI": link.info.uri,
                                "publicKey": hex::encode(link.info.remote_key.as_bytes()),
                                "ipAddress": link.info.remote_addr_v6,
                                "remote": link.info.remote_addr.to_string(),
                                "port": link.info.peer_port,
                                "up": link.alive,
                                "inbound": !link.info.outbound,
                                "uptime": uptime,
                                "latency": 0u64,
                                "RXBytes": link.rx_bytes,
                                "TXBytes": link.tx_bytes,
                                "RXRate": 0u64,
                                "TXRate": 0u64,
                                "priority": link.info.priority as u64,
                                "cost": 0u64,
                                "last_error": link.info.last_error.clone().unwrap_or_default(),
                                "last_error_time": last_error_time,
                            })
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                Ok(serde_json::json!({
                    "peers": peers
                }))
            },
        );

        // getTree - Get spanning tree
        self.add_handler("getTree", "Show known Tree entries", vec![], |_, ctx| {
            let parent = hex::encode(ctx.core.public_key().as_bytes());
            let tree = ctx
                .links
                .as_ref()
                .map(|links| {
                    links
                        .get_links()
                        .into_iter()
                        .map(|link| {
                            serde_json::json!({
                                "publicKey": hex::encode(link.info.remote_key.as_bytes()),
                                "ipAddress": link.info.remote_addr_v6,
                                "parent": parent,
                                "sequence": 0u64,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            Ok(serde_json::json!({
                "tree": tree
            }))
        });

        // getPaths - Get known paths
        self.add_handler(
            "getPaths",
            "Show established paths through this node",
            vec![],
            |_, ctx| {
                let paths = ctx
                    .links
                    .as_ref()
                    .map(|links| {
                        links
                            .get_links()
                            .into_iter()
                            .map(|link| {
                                serde_json::json!({
                                    "publicKey": hex::encode(link.info.remote_key.as_bytes()),
                                    "ipAddress": link.info.remote_addr_v6,
                                    "path": vec![link.info.peer_port as u64],
                                    "sequence": 0u64,
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                Ok(serde_json::json!({
                    "paths": paths
                }))
            },
        );

        // getSessions - Get active sessions
        self.add_handler(
            "getSessions",
            "Show established traffic sessions with remote nodes",
            vec![],
            |_, ctx| {
                let sessions = ctx
                    .core
                    .sessions()
                    .list_sessions()
                    .into_iter()
                    .map(|session| {
                        let ip_address = yggdrasil_address::addr_for_key(&session.peer)
                            .map(|a| a.to_string())
                            .unwrap_or_default();

                        serde_json::json!({
                            "publicKey": hex::encode(session.peer.as_bytes()),
                            "ipAddress": ip_address,
                            "uptime": session.since.elapsed().as_secs_f64(),
                            "RXBytes": session.rx_bytes,
                            "TXBytes": session.tx_bytes,
                        })
                    })
                    .collect::<Vec<_>>();

                Ok(serde_json::json!({
                    "sessions": sessions
                }))
            },
        );

        // getTUN - Get TUN info
        self.add_handler("getTUN", "Show TUN interface status", vec![], |_, ctx| {
            Ok(serde_json::json!({
                "enabled": ctx.tun_enabled,
                "name": ctx.tun_name.clone().unwrap_or_default(),
                "MTU": ctx.tun_mtu.unwrap_or(0),
            }))
        });

        // addPeer - Add a peer
        self.add_handler(
            "addPeer",
            "Add a peer to the peer list",
            vec!["uri", "interface"],
            |args, ctx| {
                let uri = args
                    .as_ref()
                    .and_then(|v| v.get("uri"))
                    .and_then(|u| u.as_str())
                    .ok_or("uri required")?
                    .to_string();
                let interface = args
                    .as_ref()
                    .and_then(|v| v.get("interface"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();

                if let Some(links) = &ctx.links {
                    let links = Arc::clone(links);
                    let uri_clone = uri.clone();
                    let interface_clone = interface.clone();
                    tokio::spawn(async move {
                        if let Err(e) = links
                            .connect_uri(&uri_clone, &interface_clone, LinkType::Persistent, 0, &[])
                            .await
                        {
                            tracing::warn!(uri = uri_clone, error = %e, "Failed to connect peer");
                        }
                    });
                } else {
                    return Err("links manager not initialised".to_string());
                }

                tracing::info!(uri = uri, interface = interface, "Adding peer");
                Ok(serde_json::json!({}))
            },
        );

        // removePeer - Remove a peer
        self.add_handler(
            "removePeer",
            "Remove a peer from the peer list",
            vec!["uri", "interface"],
            |args, ctx| {
                let uri = args
                    .as_ref()
                    .and_then(|v| v.get("uri"))
                    .and_then(|u| u.as_str())
                    .ok_or("uri required")?
                    .to_string();

                if let Some(links) = &ctx.links {
                    let removed = links
                        .disconnect(&uri)
                        .map_err(|e| format!("failed to remove peer: {}", e))?;
                    if !removed {
                        return Err("peer not found".to_string());
                    }
                } else {
                    return Err("links manager not initialised".to_string());
                }

                tracing::info!(uri = uri, "Removing peer");
                Ok(serde_json::json!({}))
            },
        );
    }

    /// Start the admin server.
    pub async fn start(&self) -> Result<(), AdminServerError> {
        {
            let mut running = self.running.write();
            if *running {
                return Err(AdminServerError::AlreadyStarted);
            }
            *running = true;
        }

        // Parse the listen address
        if self.listen_addr.is_empty() || self.listen_addr == "none" {
            tracing::debug!("Admin socket disabled");
            return Ok(());
        }

        let listen_addr = self.listen_addr.clone();
        let handlers = self.handlers.read();
        let handlers_clone: HashMap<String, (String, Vec<String>)> = handlers
            .iter()
            .map(|(k, v)| (k.clone(), (v.description.clone(), v.args.clone())))
            .collect();
        drop(handlers);

        if listen_addr.starts_with("tcp://") {
            let addr = listen_addr
                .strip_prefix("tcp://")
                .ok_or_else(|| AdminServerError::InvalidEndpoint(listen_addr.clone()))?;

            let listener = TcpListener::bind(addr).await?;
            tracing::info!(address = addr, "Admin socket listening on TCP");

            let context = Arc::clone(&self.context);
            let handlers_ref = Arc::new(
                self.handlers
                    .read()
                    .iter()
                    .map(|(k, v)| (k.clone(), (v.description.clone(), v.args.clone())))
                    .collect::<HashMap<_, _>>(),
            );
            let mut shutdown_rx = self.shutdown_tx.subscribe();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((stream, addr)) => {
                                    tracing::debug!(peer = %addr, "Admin connection accepted");
                                    let ctx = Arc::clone(&context);
                                    let handlers = Arc::clone(&handlers_ref);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_tcp_connection(stream, ctx, handlers).await {
                                            tracing::debug!(error = %e, "Admin connection error");
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to accept admin connection");
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::debug!("Admin server shutting down");
                            break;
                        }
                    }
                }
            });
        } else if listen_addr.starts_with("unix://") {
            #[cfg(unix)]
            {
                let path = listen_addr
                    .strip_prefix("unix://")
                    .ok_or_else(|| AdminServerError::InvalidEndpoint(listen_addr.clone()))?;

                // Clean up old socket if it exists
                if std::path::Path::new(path).exists() {
                    std::fs::remove_file(path)?;
                }

                // Create parent directory if needed
                if let Some(parent) = std::path::Path::new(path).parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let listener = UnixListener::bind(path)?;
                tracing::info!(path = path, "Admin socket listening on Unix socket");

                let context = Arc::clone(&self.context);
                let handlers_ref = Arc::new(handlers_clone);
                let mut shutdown_rx = self.shutdown_tx.subscribe();

                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            result = listener.accept() => {
                                match result {
                                    Ok((stream, _)) => {
                                        tracing::debug!("Admin connection accepted");
                                        let ctx = Arc::clone(&context);
                                        let handlers = Arc::clone(&handlers_ref);
                                        tokio::spawn(async move {
                                            if let Err(e) = handle_unix_connection(stream, ctx, handlers).await {
                                                tracing::debug!(error = %e, "Admin connection error");
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "Failed to accept admin connection");
                                    }
                                }
                            }
                            _ = shutdown_rx.recv() => {
                                tracing::debug!("Admin server shutting down");
                                break;
                            }
                        }
                    }
                });
            }
            #[cfg(not(unix))]
            {
                return Err(AdminServerError::InvalidEndpoint(
                    "Unix sockets not supported on this platform".to_string(),
                ));
            }
        } else {
            // Assume plain TCP
            let listener = TcpListener::bind(&listen_addr).await?;
            tracing::info!(address = %listen_addr, "Admin socket listening on TCP");

            let context = Arc::clone(&self.context);
            let handlers_ref = Arc::new(handlers_clone);
            let mut shutdown_rx = self.shutdown_tx.subscribe();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((stream, addr)) => {
                                    tracing::debug!(peer = %addr, "Admin connection accepted");
                                    let ctx = Arc::clone(&context);
                                    let handlers = Arc::clone(&handlers_ref);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_tcp_connection(stream, ctx, handlers).await {
                                            tracing::debug!(error = %e, "Admin connection error");
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to accept admin connection");
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::debug!("Admin server shutting down");
                            break;
                        }
                    }
                }
            });
        }

        Ok(())
    }

    /// Stop the admin server.
    pub async fn stop(&self) -> Result<(), AdminServerError> {
        let mut running = self.running.write();
        if !*running {
            return Ok(());
        }
        *running = false;

        let _ = self.shutdown_tx.send(());
        tracing::info!("Admin server stopped");
        Ok(())
    }

    /// Check if running.
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Get a list of handlers for the list command.
    pub fn get_handler_list(&self) -> Vec<(String, String, Vec<String>)> {
        let handlers = self.handlers.read();
        let mut list: Vec<_> = handlers
            .iter()
            .map(|(name, h)| (name.clone(), h.description.clone(), h.args.clone()))
            .collect();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        list
    }

    /// Handle a request.
    pub fn handle_request(&self, request: &AdminRequest) -> AdminResponse {
        let request_echo = AdminRequestEcho {
            request: request.name.clone(),
            arguments: request.arguments.clone(),
        };

        // Special handling for 'list' command
        if request.name.to_lowercase() == "list" {
            let handlers = self.handlers.read();
            let mut list: Vec<serde_json::Value> = handlers
                .iter()
                .map(|(name, h)| {
                    serde_json::json!({
                        "command": name,
                        "description": h.description,
                        "fields": h.args,
                    })
                })
                .collect();
            list.sort_by(|a, b| {
                a.get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .cmp(b.get("command").and_then(|v| v.as_str()).unwrap_or(""))
            });

            return AdminResponse {
                status: "success".to_string(),
                error: None,
                request: request_echo,
                response: Some(serde_json::json!({ "list": list })),
            };
        }

        let handlers = self.handlers.read();
        let name_lower = request.name.to_lowercase();

        if let Some(handler) = handlers.get(&name_lower) {
            let ctx = self.context.read();
            match (handler.handler)(request.arguments.clone(), &ctx) {
                Ok(response) => AdminResponse {
                    status: "success".to_string(),
                    error: None,
                    request: request_echo,
                    response: Some(response),
                },
                Err(e) => AdminResponse {
                    status: "error".to_string(),
                    error: Some(e),
                    request: request_echo,
                    response: None,
                },
            }
        } else {
            AdminResponse {
                status: "error".to_string(),
                error: Some(format!(
                    "Unknown action '{}', try 'list' for help",
                    request.name
                )),
                request: request_echo,
                response: None,
            }
        }
    }
}

async fn handle_tcp_connection(
    stream: TcpStream,
    context: Arc<RwLock<AdminContext>>,
    _handlers: Arc<HashMap<String, (String, Vec<String>)>>,
) -> Result<(), AdminServerError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // Connection closed
        }

        let request: AdminRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                let response = AdminResponse {
                    status: "error".to_string(),
                    error: Some(format!("Failed to parse request: {}", e)),
                    request: AdminRequestEcho {
                        request: String::new(),
                        arguments: None,
                    },
                    response: None,
                };
                let response_json = serde_json::to_string(&response)?;
                writer.write_all(response_json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
                continue;
            }
        };

        let keepalive = request.keepalive;
        let response = handle_request_with_context(&request, &context);
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        if !keepalive {
            break;
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn handle_unix_connection(
    stream: UnixStream,
    context: Arc<RwLock<AdminContext>>,
    _handlers: Arc<HashMap<String, (String, Vec<String>)>>,
) -> Result<(), AdminServerError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let request: AdminRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                let response = AdminResponse {
                    status: "error".to_string(),
                    error: Some(format!("Failed to parse request: {}", e)),
                    request: AdminRequestEcho {
                        request: String::new(),
                        arguments: None,
                    },
                    response: None,
                };
                let response_json = serde_json::to_string(&response)?;
                writer.write_all(response_json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
                continue;
            }
        };

        let keepalive = request.keepalive;
        let response = handle_request_with_context(&request, &context);
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        if !keepalive {
            break;
        }
    }

    Ok(())
}

fn handle_request_with_context(
    request: &AdminRequest,
    context: &Arc<RwLock<AdminContext>>,
) -> AdminResponse {
    let request_echo = AdminRequestEcho {
        request: request.name.clone(),
        arguments: request.arguments.clone(),
    };

    let ctx = context.read();

    // Handle built-in commands
    match request.name.to_lowercase().as_str() {
        "list" => {
            // Return a basic list since we don't have access to all handlers here
            // This is handled by the AdminServer itself normally
            let list = vec![
                serde_json::json!({
                    "command": "getSelf",
                    "description": "Show details about this node",
                    "fields": []
                }),
                serde_json::json!({
                    "command": "getPeers",
                    "description": "Show directly connected peers",
                    "fields": ["sort"]
                }),
                serde_json::json!({
                    "command": "getTree",
                    "description": "Show known Tree entries",
                    "fields": []
                }),
                serde_json::json!({
                    "command": "getPaths",
                    "description": "Show established paths through this node",
                    "fields": []
                }),
                serde_json::json!({
                    "command": "getSessions",
                    "description": "Show established traffic sessions with remote nodes",
                    "fields": []
                }),
                serde_json::json!({
                    "command": "getTUN",
                    "description": "Show TUN interface status",
                    "fields": []
                }),
                serde_json::json!({
                    "command": "addPeer",
                    "description": "Add a peer to the peer list",
                    "fields": ["uri", "interface"]
                }),
                serde_json::json!({
                    "command": "removePeer",
                    "description": "Remove a peer from the peer list",
                    "fields": ["uri", "interface"]
                }),
                serde_json::json!({
                    "command": "list",
                    "description": "List available commands",
                    "fields": []
                }),
            ];

            AdminResponse {
                status: "success".to_string(),
                error: None,
                request: request_echo,
                response: Some(serde_json::json!({ "list": list })),
            }
        }
        "getself" => AdminResponse {
            status: "success".to_string(),
            error: None,
            request: request_echo,
            response: Some(serde_json::json!({
                "buildName": "yggdrasil",
                "buildVersion": VERSION,
                "publicKey": hex::encode(ctx.core.public_key().as_bytes()),
                "ipAddress": ctx.core.address().to_string(),
                "subnet": format!("{}/64", ctx.core.subnet()),
                "routingEntries": ctx.links.as_ref().map(|l| l.connection_count() as u64).unwrap_or(0),
            })),
        },
        "getpeers" => {
            let peers: Vec<serde_json::Value> = if let Some(links) = &ctx.links {
                links
                    .get_links()
                    .into_iter()
                    .map(|link| {
                        let uptime = link.info.established.elapsed().as_secs_f64();
                        let last_error_time = link
                            .info
                            .last_error_time
                            .map(|t| t.elapsed().as_secs_f64())
                            .unwrap_or(0.0);

                        serde_json::json!({
                            "URI": link.info.uri,
                            "publicKey": hex::encode(link.info.remote_key.as_bytes()),
                            "ipAddress": link.info.remote_addr_v6,
                            "remote": link.info.remote_addr.to_string(),
                            "port": link.info.peer_port,
                            "up": link.alive,
                            "inbound": !link.info.outbound,
                            "uptime": uptime,
                            "latency": 0u64,
                            "RXBytes": link.rx_bytes,
                            "TXBytes": link.tx_bytes,
                            "RXRate": 0u64,
                            "TXRate": 0u64,
                            "priority": link.info.priority as u64,
                            "cost": 0u64,
                            "last_error": link.info.last_error.clone().unwrap_or_default(),
                            "last_error_time": last_error_time,
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            };
            AdminResponse {
                status: "success".to_string(),
                error: None,
                request: request_echo,
                response: Some(serde_json::json!({ "peers": peers })),
            }
        }
        "gettree" => {
            let parent = hex::encode(ctx.core.public_key().as_bytes());
            let tree = ctx
                .links
                .as_ref()
                .map(|links| {
                    links
                        .get_links()
                        .into_iter()
                        .map(|link| {
                            serde_json::json!({
                                "publicKey": hex::encode(link.info.remote_key.as_bytes()),
                                "ipAddress": link.info.remote_addr_v6,
                                "parent": parent,
                                "sequence": 0u64,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            AdminResponse {
                status: "success".to_string(),
                error: None,
                request: request_echo,
                response: Some(serde_json::json!({ "tree": tree })),
            }
        }
        "getpaths" => {
            let paths = ctx
                .links
                .as_ref()
                .map(|links| {
                    links
                        .get_links()
                        .into_iter()
                        .map(|link| {
                            serde_json::json!({
                                "publicKey": hex::encode(link.info.remote_key.as_bytes()),
                                "ipAddress": link.info.remote_addr_v6,
                                "path": vec![link.info.peer_port as u64],
                                "sequence": 0u64,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            AdminResponse {
                status: "success".to_string(),
                error: None,
                request: request_echo,
                response: Some(serde_json::json!({ "paths": paths })),
            }
        }
        "getsessions" => {
            let sessions = ctx
                .core
                .sessions()
                .list_sessions()
                .into_iter()
                .map(|session| {
                    let ip_address = yggdrasil_address::addr_for_key(&session.peer)
                        .map(|a| a.to_string())
                        .unwrap_or_default();

                    serde_json::json!({
                        "publicKey": hex::encode(session.peer.as_bytes()),
                        "ipAddress": ip_address,
                        "uptime": session.since.elapsed().as_secs_f64(),
                        "RXBytes": session.rx_bytes,
                        "TXBytes": session.tx_bytes,
                    })
                })
                .collect::<Vec<_>>();

            AdminResponse {
                status: "success".to_string(),
                error: None,
                request: request_echo,
                response: Some(serde_json::json!({ "sessions": sessions })),
            }
        }
        "gettun" => AdminResponse {
            status: "success".to_string(),
            error: None,
            request: request_echo,
            response: Some(serde_json::json!({
                "enabled": ctx.tun_enabled,
                "name": ctx.tun_name.clone().unwrap_or_default(),
                "MTU": ctx.tun_mtu.unwrap_or(0),
            })),
        },
        "addpeer" => {
            let uri = request
                .arguments
                .as_ref()
                .and_then(|v| v.get("uri"))
                .and_then(|u| u.as_str());

            if let Some(uri) = uri {
                if let Some(links) = &ctx.links {
                    let links = Arc::clone(links);
                    let uri_string = uri.to_string();
                    tokio::spawn(async move {
                        if let Err(e) = links
                            .connect_uri(&uri_string, "", LinkType::Persistent, 0, &[])
                            .await
                        {
                            tracing::warn!(uri = uri_string, error = %e, "Failed to connect peer");
                        }
                    });

                    tracing::info!(uri = uri, "Adding peer");
                    AdminResponse {
                        status: "success".to_string(),
                        error: None,
                        request: request_echo,
                        response: Some(serde_json::json!({})),
                    }
                } else {
                    AdminResponse {
                        status: "error".to_string(),
                        error: Some("links manager not initialised".to_string()),
                        request: request_echo,
                        response: None,
                    }
                }
            } else {
                AdminResponse {
                    status: "error".to_string(),
                    error: Some("uri required".to_string()),
                    request: request_echo,
                    response: None,
                }
            }
        }
        "removepeer" => {
            let uri = request
                .arguments
                .as_ref()
                .and_then(|v| v.get("uri"))
                .and_then(|u| u.as_str());

            if let Some(uri) = uri {
                if let Some(links) = &ctx.links {
                    match links.disconnect(uri) {
                        Ok(true) => {
                            tracing::info!(uri = uri, "Removing peer");
                            AdminResponse {
                                status: "success".to_string(),
                                error: None,
                                request: request_echo,
                                response: Some(serde_json::json!({})),
                            }
                        }
                        Ok(false) => AdminResponse {
                            status: "error".to_string(),
                            error: Some("peer not found".to_string()),
                            request: request_echo,
                            response: None,
                        },
                        Err(e) => AdminResponse {
                            status: "error".to_string(),
                            error: Some(format!("failed to remove peer: {}", e)),
                            request: request_echo,
                            response: None,
                        },
                    }
                } else {
                    AdminResponse {
                        status: "error".to_string(),
                        error: Some("links manager not initialised".to_string()),
                        request: request_echo,
                        response: None,
                    }
                }
            } else {
                AdminResponse {
                    status: "error".to_string(),
                    error: Some("uri required".to_string()),
                    request: request_echo,
                    response: None,
                }
            }
        }
        _ => AdminResponse {
            status: "error".to_string(),
            error: Some(format!(
                "Unknown action '{}', try 'list' for help",
                request.name
            )),
            request: request_echo,
            response: None,
        },
    }
}
