# File: thirdparty/yggdrasil-go/cmd/yggdrasilctl/main.go

Purpose: CLI client for the admin socket; parses command-line arguments, connects over TCP or UNIX socket, sends an admin request, and formats the response (table or JSON).

Key points
- Uses `protect.Pledge` to limit syscalls; main delegates to `run()` for error-aware exit codes and buffered logging.
- Resolves endpoint from environment/flags via `cmdLineEnv` (defined in `cmd_line_env.go`), supports `unix://` and `tcp://` endpoints, defaults to TCP if scheme missing.
- Marshals `admin.AdminSocketRequest` with command name and key=value arguments, sends via JSON, and decodes `AdminSocketResponse`; errors printed and return code 1 on failure.
- When not `-json`, renders responses with `tablewriter`:
  - `list`: command list with required fields.
  - `getSelf`: build name/version, IP, subnet, routing table size, public key.
  - `getPeers`: rows per peer with state, direction, IP, uptime, RTT, RX/TX bytes and rates, priority, cost, last error time/message.
  - `getTree`, `getPaths`, `getSessions`, `getNodeInfo`, `getMulticastInterfaces`, `getTun` have dedicated table layouts; `addPeer`/`removePeer` send request without output.
- Keeps connection open only for one request/response; uses basic panic recovery to dump buffered logs on fatal error.

Rust parity
- Rust CLI folds admin commands into `src/main.rs` subcommands (`getself`, `getpeers`, `gettree`, `getpaths`, `getsessions`, `gettun`, `addpeer`, `removepeer`, `list`, `raw`) executed via `AdminClient`. Output can be JSON or table using `comfy_table`; command parsing handled by Clap rather than custom env parser.
- Endpoint handling analogous (default `tcp://localhost:9001`), but Rust uses async admin client and integrates with the daemon CLI; does not use `protect.Pledge` or `tablewriter`.
