# Contributing guide

Thank you for investing your time in contributing to I/O OAuth.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya ARCHITECTURE](https://github.com/pimalaya/.github/blob/master/ARCHITECTURE.md) for the conventions every repository shares (layering, `no_std`, modules, errors, code style, licensing, notes for AI agents);
3. the inline header documentation, starting with [`src/lib.rs`](src/lib.rs), for how this crate is architectured: its `lib.rs` *is* the architecture document (the RFC-per-folder layout, the intentional omissions, and the conventions), and every coroutine module opens with a runnable usage example;
4. this guide, for how to build, test and submit changes here.

## Development environment

The environment is managed by [Nix](https://nixos.org/download.html). `nix develop` spawns a shell with the right toolchain; every cargo command below assumes it (or prefix them with `nix develop --command`).

Without Nix, install a recent stable toolchain via [rustup](https://rust-lang.github.io/rustup/) (`rustup update`); the crate needs Rust matching the `rust-version` in [Cargo.toml](./Cargo.toml).

## Build

I/O OAuth is a `#![no_std]` library (with `alloc`) built on [io-http](https://github.com/pimalaya/io-http), exposing three feature-gated layers:

- the I/O-free coroutines: no feature required, `no_std`, no sockets nor async runtime;
- the light client (`client` feature): a std-blocking `Oauth20ClientStd` wrapping any `Read + Write` stream you opened yourself;
- the full client (`rustls-ring` (default), `rustls-aws` or `native-tls`): opens the TCP/TLS connection itself via [pimalaya/stream](https://github.com/pimalaya/stream).

Check every layer, since gated code (`client`, `std`, TLS) must not leak into the always-on coroutine core:

```sh
cargo build --no-default-features                    # coroutines only, no std leak
cargo build --no-default-features --features client  # light client, no TLS deps
cargo build --release                                # full client (rustls-ring)
```

When touching feature gates or imports, build with and without each feature so no gated code leaks into the core.

## Lint, test, audit

```sh
cargo test --all-features                    # unit + doc tests
cargo clippy --all-targets --all-features
cargo fmt                                    # CI checks `cargo fmt --check`
```

Every public item (types, fields, variants) carries a `///` doc, and the coroutine module examples are real doctests. Keep both complete across the feature matrix:

```sh
RUSTFLAGS="-D missing_docs" cargo check --all-features
RUSTFLAGS="-D missing_docs" cargo check                       # feature-gated modules too
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc --all-features
```

The runnable examples live in [./examples](examples); run one with `cargo run --example <name>` (see [auth_code_grant](examples/auth_code_grant.rs) and [device_auth_grant](examples/device_auth_grant.rs), which need a TLS feature).

## Override dependencies

All Pimalaya crates use `[patch.crates-io]` to point to sibling directories. To build I/O OAuth against a locally modified dependency (e.g. `io-http`), add to `Cargo.toml`:

```toml
[patch.crates-io]
io-http.path = "/path/to/io-http"
```

## Commit style

I/O OAuth follows the [conventional commits specification](https://www.conventionalcommits.org/en/v1.0.0/#summary). Keep the subject imperative and scoped; describe the *why* in the body when it is not obvious.
