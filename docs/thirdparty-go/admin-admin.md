# File: thirdparty/yggdrasil-go/src/admin/admin.go

Purpose: admin socket server for yggdrasil-go; registers handlers, listens on TCP/UNIX, processes JSON requests, and dispatches to core handlers.

Key points
- `New` sets up listener (tcp/unix) with cleanup of stale UNIX sockets, initializes handler map, registers built-in `list`, starts accept loop, and binds admin to `core.Core` via `SetAdmin`.
- `SetupAdminHandlers` wires endpoints: `getSelf`, `getPeers`, `getTree`, `getPaths`, `getSessions`, `addPeer`, `removePeer`, each wrapping request/response structs and delegating to handler methods (`getSelfHandler` etc.).
- Request/response model: `AdminSocketRequest{request, arguments, keepalive}` and `AdminSocketResponse{status,error,request,response}`. Decoder disallows unknown fields. Errors returned as status="error" with message.
- `handleRequest` supports persistent connections via `KeepAlive`, otherwise closes after one response. `DataUnit` helper formats byte counts.

Rust parity
- Rust admin server is in `src/admin_server.rs` and `yggdrasil::AdminServer`. Handlers mapped similarly and recently filled TODOs to fetch real data. Rust uses async (tokio), structured response types, and does not support keepalive per request; each HTTP/WebSocket? uses JSON over TCP? (current Rust admin uses async TCP JSON with one-shot responses).
- Rust listener setup differs: uses config/admin listen from `NodeConfig`, and error handling differs (no UNIX socket cleanup logic like Go `@` abstract namespace handling). Authentication still TODO in both.
