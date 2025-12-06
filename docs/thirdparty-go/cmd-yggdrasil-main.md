# File: thirdparty/yggdrasil-go/cmd/yggdrasil/main.go

Purpose: primary daemon entrypoint for the Go implementation; parses CLI flags, loads/normalizes config, instantiates core, admin socket, multicast, and TUN modules, and blocks until shutdown.

Key points
- CLI flags cover generating/using config (`-genconf`, `-useconf`, `-useconffile`, `-normaliseconf`, `-exportkey`, JSON/HJSON output), autoconf mode, address/subnet/public key printing, log target/level, user switching, and version info.
- Config handling: uses `config.GenerateConfig()` defaults, supports reading HJSON/JSON from stdin or file, normalizes by stripping admin listen/privkey path, optional PEM export of private key, and derive address/subnet from ed25519 key.
- Core setup: builds `core.New` with options (node info/privacy, peer filter that drops `200::/7`, listen addresses, peers/interface peers, allowed pubkeys). Logs public key/address/subnet after start.
- Admin/multicast/TUN: creates admin socket (`admin.New` + `SetupAdminHandlers`), multicast (`multicast.New` + admin handlers, per-interface options with regex/priority/password), and TUN adapter (`tun.New` + admin handlers). Uses `ipv6rwc` as I/O for TUN.
- Shutdown and privileges: registers Windows service exit callback, optional `chuser` UID/GID drop, then `protect.Pledge` with permitted modes based on config (adds `mcast` if interfaces configured); blocks on signal context, then stops admin, multicast, TUN, and core.

Rust parity
- Rust CLI in `src/main.rs` handles equivalent behaviors via subcommands (`run`, `generate-config`, `normalize-config`, `export-key`, `info`) and configuration loader in `yggdrasil_config`. It prints address/subnet/public key similarly but does not hunt for “better” keys.
- Module setup mirrors Rust’s `cmd_run` path: constructs `Core`, `AdminServer`, `Multicast`, and `TunAdapter` using options from config; Rust uses structured types (`NodeConfig`, `Links`, `MulticastConfig`, `TunConfig`) and async runtime, while Go uses blocking setup with `gologme` logger and optional syslog.
- Go binary uses `protect.Pledge` and `minwinsvc` service hooks; Rust version lacks pledge/Windows service code but includes Clap-based CLI and compatibility mode for yggdrasil-go flags.
