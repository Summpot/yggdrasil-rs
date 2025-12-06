# thirdparty/yggdrasil-go/cmd/yggdrasilctl/cmd_line_env.go

## Overview
Command-line parsing and endpoint selection helper for `yggdrasilctl`. Manages CLI flags, default admin endpoint discovery, and JSON output toggle.

## API surface
- `type CmdLineEnv`: holds parsed args (`args`), selected admin endpoint (`endpoint`, `server`), and flags (`injson`, `ver`).
- `newCmdLineEnv() CmdLineEnv`: initializes with `DefaultAdminListen` from config defaults.
- `(*CmdLineEnv) parseFlagsAndArgs()`: defines flags `-endpoint`, `-json`, `-version`, installs custom usage text, parses, and stores positional args.
- `(*CmdLineEnv) setEndpoint(logger *log.Logger)`: if CLI endpoint matches the platform default, attempts to read the default config file:
  - Handles UTF-16 BOM using `unicode.UTF16` decoder.
  - `hjson.Unmarshal` to map and read `AdminListen`.
  - If `AdminListen` is a non-empty/non-"none" string, adopts it; otherwise logs fallback to default.
  - If config load fails, logs fallback.
  - If CLI endpoint differs, uses CLI value and logs the choice.

## Behavioural notes
- Only inspects the default config path from `config.GetDefaults()`; does not load user-specified configs.
- Accepts both pretty and JSON output flags but leaves rendering to callers.
- Panics on HJSON decode errors rather than returning them.

## Comparison to yggdrasil-rs
- Rust tree lacks an equivalent CLI helper for `yggdrasilctl`; admin client in `src/admin.rs` handles only direct TCP/Unix endpoints supplied by the caller, without auto-discovering `AdminListen` from config files or BOM-aware HJSON parsing.
- Parity gap: discover default admin endpoint from config (including UTF-16 BOM handling), support `-json`/`-version` flags, and provide user-facing usage text consistent with Go CLI.
