# thirdparty/yggdrasil-go/cmd/yggdrasil/chuser_*.go

## Overview
User/group dropping helper behind build tags. Provides a platform-specific `chuser` that parses `user[:group]` and switches effective UID/GID/groups for the daemon. Non-Unix builds return a single error.

## API surface
- `chuser(user string) error` (Unix platforms):
  - Parses `user[:group]` with `strings.Cut`.
  - Rejects empty user or empty group when delimiter present.
  - Looks up UID by numeric ID or username (`user.LookupId` fallback to `Lookup`).
  - Resolves target GID from explicit group or default user primary group (`user.LookupGroupId`/`LookupGroup`).
  - Applies `setgroups([gid])`, `setgid`, then `setuid` via `unix` syscalls.
- `chuser(user string) error` (other platforms): always returns "setting uid/gid is not supported on this platform".

## Tests (chuser_unix_test.go)
Covers negative cases (empty input, empty group, group-only, invalid username `#user`, negative UID) and positive cases when running as root:
- Switching to current UID by numeric string.
- Switching to `nobody` user when present.

## Behavioural notes
- Allows specifying user or user:group; coerces IDs via `strconv.Atoi`.
- Uses only a single supplementary group (the target GID) through `Setgroups` before `Setgid/Setuid`.
- Errors and last error timestamps are not propagated—callers just see the returned error.

## Comparison to yggdrasil-rs
- No equivalent privilege-drop helper exists in the Rust tree (grep shows no `setuid/setgid` usage). The daemon currently runs without an option to lower privileges after start.
- If parity is desired, a Rust-side implementation would need platform-gated UID/GID switching and CLI/config plumbing mirroring `chuser` semantics and validation.
