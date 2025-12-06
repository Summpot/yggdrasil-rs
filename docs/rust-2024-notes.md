# Rust 2024 Edition Notes

This project uses Rust 2024 edition (as specified in `Cargo.toml`).

## Rand Crate API Changes

The rand 0.9 crate has updated APIs for the Rust 2024 edition:

### Old API (Rust 2021 and earlier)
```rust
use rand::Rng;

let value = rand::thread_rng().gen_range(0..100);
let random = rand::thread_rng().gen();
```

### New API (Rust 2024)
```rust
let value = rand::rng().random_range(0..100);
let random = rand::rng().random();
```

### Why the Change?

1. **Keyword Conflict**: Rust 2024 introduces `gen` as a reserved keyword for generator syntax
2. **Simpler Names**: `rng()` is shorter than `thread_rng()`
3. **Better Naming**: `random()` is more descriptive than `gen()`

### Deprecation Warnings

When building with Rust 2024 edition, the old API functions are deprecated:
- `rand::thread_rng()` is deprecated, renamed to `rand::rng()`
- `Rng::gen_range()` is deprecated, renamed to `random_range()`
- `Rng::r#gen()` is deprecated, renamed to `random()` (the `r#` prefix was needed to avoid the keyword)

### Current Usage in This Project

All deprecated rand API calls have been updated to use the new Rust 2024 API:

**crates/yggdrasil-multicast/src/multicast.rs:614**
```rust
let delay = Duration::from_millis(1000 + rand::rng().random_range(0..1048));
```

**crates/yggdrasil-routing/src/router.rs:139**
```rust
let nonce = rand::rng().random();
```

### Verification

These changes are verified by:
1. Clean build with zero warnings: `cargo check --all-targets`
2. All tests passing: `cargo test --workspace`
3. Code compiles successfully: `cargo build`

## References

- Rust 2024 Edition Guide: https://doc.rust-lang.org/edition-guide/rust-2024/index.html
- Rand 0.9 Release Notes: https://github.com/rust-random/rand/releases/tag/0.9.0
- Edition Migration: The project Cargo.toml explicitly sets `edition = "2024"` and `rust-version = "1.85"`

## Compatibility Note

If you see errors about `random_range` or `random` not being found:
1. Ensure you're using Rust 1.85 or later: `rustc --version`
2. Ensure the project is using edition 2024 (check `Cargo.toml`)
3. Update your rust toolchain: `rustup update`
