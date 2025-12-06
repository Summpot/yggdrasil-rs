# File: thirdparty/yggdrasil-go/cmd/genkeys/main.go

Purpose: stand-alone key generator CLI that hunts for an ed25519 key with a “better” (lexicographically smaller) public key and prints each improvement with derived Yggdrasil address.

Key points
- Spawns `GOMAXPROCS` goroutines (`doKeys`) that loop generating ed25519 keypairs; tracks the best pubkey seen via `isBetter` and sends improvements on a channel.
- `isBetter` compares byte slices to prefer lexicographically smaller public keys (comment claims “higher NodeID”, but implementation chooses smaller values starting from 0xff bytes).
- On improvement, prints private/public keys (hex) and derived IPv6 address from `address.AddrForKey`; maintains total keys tested.
- Uses `suah.dev/protect.Pledge("stdio")` to restrict syscalls after startup.

Rust parity
- Closest equivalent is `cmd_generate_keys` in `src/main.rs`, which generates a single keypair and prints private/public key plus derived address and subnet; it does **not** iterate to find an “optimal” key or perform syscall pledging.
- No Rust counterpart for a “-sig” mode or any best-key search heuristic; current Rust CLI only emits one keypair per invocation.
