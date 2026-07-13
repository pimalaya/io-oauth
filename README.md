# I/O OAuth [![Documentation](https://img.shields.io/docsrs/io-oauth?style=flat&logo=docs.rs&logoColor=white)](https://docs.rs/io-oauth/latest/io_oauth) [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

OAuth client library for Rust

This library is composed of 3 feature-gated layers:

- Low-level **I/O-free** coroutines: these `no_std`-compatible state machines contain the whole OAuth logic and can be used anywhere
- Mid-level **light client**: a standard, blocking client using a `Stream: Read + Write`
- High-level **full client**: light client + TCP connections and TLS negotiations handled for you

## Table of contents

- [Features](#features)
- [RFC coverage](#rfc-coverage)
- [Usage](#usage)
  - [Coroutine](#coroutine)
  - [Light client](#light-client)
  - [Full client](#full-client)
- [Examples](#examples)
- [AI disclosure](#ai-disclosure)
- [License](#license)
- [Social](#social)
- [Sponsoring](#sponsoring)

## Features

- **I/O-free** coroutines: `no_std` state machines; no sockets, no async runtime, no `std` required, drive against any blocking, async, or fuzz harness.
- **Grants**: authorization code (RFC 6749 §4.1) with PKCE (RFC 7636), client credentials (§4.4), device authorization (RFC 8628).
- **Token lifecycle**: issue (§5) and refresh (§6) access tokens.
- **Dynamic client registration** (RFC 7591): register a public client with no console nor secret.
- Light standard, blocking client (requires `client` feature)
- Full standard, blocking client with **TLS** support:
  - [Rustls](https://crates.io/crates/rustls) with ring crypto (requires `rustls-ring` feature, enabled by default)
  - [Rustls](https://crates.io/crates/rustls) with aws crypto (requires `rustls-aws` feature)
  - [Native TLS](https://crates.io/crates/native-tls) (requires `native-tls` feature)

> [!TIP]
> I/O OAuth is written in [Rust](https://www.rust-lang.org/) and uses [cargo features](https://doc.rust-lang.org/cargo/reference/features.html) to gate backend support. The default feature set is declared in [Cargo.toml](./Cargo.toml) or on [docs.rs](https://docs.rs/crate/io-oauth/latest/features).

## RFC coverage

| Module   | What it covers                                                                                                              |
|----------|---------------------------------------------------------------------------------------------------------------------------|
| [6749]   | OAuth 2.0 framework: authorization code grant (`Oauth20RequestAccessToken`), client credentials (`Oauth20RequestClientCredentials`), token issue/refresh (`Oauth20RefreshAccessToken`), CSRF state, and the std client `Oauth20ClientStd` |
| [7591]   | Dynamic client registration: `Oauth20RegisterClient` coroutine                                                            |
| [7636]   | PKCE: `Oauth20PkceCodeChallenge` / `Oauth20PkceCodeVerifier`                                                              |
| [8628]   | Device authorization grant: `Oauth20RequestDeviceAuth` and `Oauth20RequestDeviceAccessToken` coroutines                   |

[6749]: https://www.rfc-editor.org/rfc/rfc6749
[7591]: https://www.rfc-editor.org/rfc/rfc7591
[7636]: https://www.rfc-editor.org/rfc/rfc7636
[8628]: https://www.rfc-editor.org/rfc/rfc8628

## Usage

I/O OAuth can be consumed three ways, depending on how much of the I/O stack you want to own. Each mode is gated by cargo features.

Every coroutine exposes `new(request, params)` plus a `resume(arg: Option<&[u8]>)` method returning a per-coroutine result enum with four variants:

- `WantsRead`: the coroutine wants bytes read from the socket and handed back on the next `resume`.
- `WantsWrite(Vec<u8>)`: the coroutine wants these bytes written to the socket.
- `Ok(..)`: terminal; carries the parsed response (a `Result` of success or error params).
- `Err(..)`: terminal; the coroutine itself failed (transport, parsing, unexpected redirect).

### Coroutine

No features required: works in `#![no_std]`, no sockets, no async runtime. You own the loop and the bytes; the library only produces request bytes and consumes server responses.

```toml,ignore
[dependencies]
io-oauth = { version = "0.1", default-features = false }
```

Exchange an authorization code for an access token (the same shape works under blocking, async, or in-memory replay):

```rust,no_run
use std::{
    io::{Read, Write},
    net::TcpStream,
};

use io_http::rfc9110::request::HttpRequest;
use io_oauth::rfc6749::access_token_request::{
    Oauth20RequestAccessToken, Oauth20RequestAccessTokenParams, Oauth20RequestAccessTokenResult,
};
use url::Url;

let token_url = Url::parse("https://example.com/token").unwrap();
let request = HttpRequest {
    method: "POST".into(),
    url: token_url.clone(),
    headers: Vec::new(),
    body: Vec::new(),
}
.header("Host", token_url.host_str().unwrap());

let params = Oauth20RequestAccessTokenParams {
    code: "the-authorization-code".into(),
    redirect_uri: None,
    client_id: "client-id".into(),
    client_secret: None,
    pkce_code_verifier: None,
};

let mut stream = TcpStream::connect("example.com:443").unwrap();
let mut coroutine = Oauth20RequestAccessToken::new(request, params);
let mut arg: Option<&[u8]> = None;
let mut buf = [0u8; 4096];

let response = loop {
    match coroutine.resume(arg.take()) {
        Oauth20RequestAccessTokenResult::Ok(res) => break res,
        Oauth20RequestAccessTokenResult::WantsRead => {
            let n = stream.read(&mut buf).unwrap();
            arg = Some(&buf[..n]);
        }
        Oauth20RequestAccessTokenResult::WantsWrite(bytes) => {
            stream.write_all(&bytes).unwrap();
        }
        Oauth20RequestAccessTokenResult::Err(err) => panic!("{err}"),
    }
};

println!("issued: {}", response.is_ok());
```

### Light client

Enable the `client` feature. `Oauth20ClientStd::new(stream, token_endpoint, client_id)` wraps any blocking `Read + Write + Send` and runs the coroutine loop for you. You still open the TCP socket and run TLS yourself, then hand over a ready-to-talk stream; the client takes it from there.

```toml,ignore
[dependencies]
io-oauth = { version = "0.1", default-features = false, features = ["client"] }
```

```rust,no_run
use std::net::TcpStream;

use io_oauth::rfc6749::{
    access_token_request::Oauth20RequestAccessTokenParams, client::Oauth20ClientStd,
};
use url::Url;

let token_url = Url::parse("https://example.com/token").unwrap();

// open (and, for https, TLS-wrap) the stream yourself:
let stream = TcpStream::connect("example.com:443").unwrap();
let mut client = Oauth20ClientStd::new(stream, token_url, "client-id");

let params = Oauth20RequestAccessTokenParams {
    code: "the-authorization-code".into(),
    redirect_uri: None,
    client_id: "client-id".into(),
    client_secret: None,
    pkce_code_verifier: None,
};

let response = client.request_access_token(params).unwrap();
println!("issued: {}", response.is_ok());
```

### Full client

Enable one of the TLS feature flags: `rustls-ring` (default), `rustls-aws`, or `native-tls`. `Oauth20ClientStd::connect(token_endpoint, tls, client_id)` opens `http://` (plain TCP) or `https://` (implicit TLS) via [pimalaya/stream](https://github.com/pimalaya/stream), returning a ready-to-use client.

```toml,ignore
[dependencies]
io-oauth = "0.1" # rustls-ring is enabled by default
```

```rust,no_run
use io_oauth::rfc6749::{
    access_token_request::Oauth20RequestAccessTokenParams, client::Oauth20ClientStd,
};
use pimalaya_stream::tls::Tls;
use url::Url;

let token_url = Url::parse("https://example.com/token").unwrap();
let tls = Tls::default();
let mut client = Oauth20ClientStd::connect(token_url, &tls, "client-id").unwrap();

let params = Oauth20RequestAccessTokenParams {
    code: "the-authorization-code".into(),
    redirect_uri: None,
    client_id: "client-id".into(),
    client_secret: None,
    pkce_code_verifier: None,
};

let response = client.request_access_token(params).unwrap();
println!("issued: {}", response.is_ok());
```

## Examples

See complete examples at [./examples](https://github.com/pimalaya/io-oauth/blob/master/examples).

Have also a look at real-world projects built on top of this library:

- [Ortie](https://github.com/pimalaya/ortie): CLI to manage OAuth access tokens
- [Cardamum](https://github.com/pimalaya/cardamum): CLI to manage contacts

## AI disclosure

This project is developed with AI assistance. This section documents how, so users and downstream packagers can make informed decisions.

- **Tools**: Claude Code (Anthropic), Opus 4.8, invoked locally with a persistent project-scoped memory and a small set of repo-specific rules.

- **Used for**: Refactors, mechanical multi-file edits, boilerplate (feature gates, error enums, derive macros, trait impls), test scaffolding, doc polish, exploratory design conversations.

- **Not used for**: Engineering, critical code, git manipulation (commit, merge, rebase…), real-world tests.

- **Verification**: Every AI-assisted change is read, compiled, tested, and formatted before commit (`nix develop --command cargo check / cargo test / cargo fmt`). Behavioural correctness is verified against the relevant RFC or upstream spec, not assumed from the model output. Tests are never adjusted to fit AI-generated code; the code is adjusted to fit correct behaviour.

- **Limitations**: AI models occasionally produce code that compiles and passes tests but is subtly wrong: off-by-one errors, missed edge cases, plausible but nonexistent APIs, stale RFC references. The verification workflow catches most of this; it does not catch all of it. Bug reports are welcome and taken seriously.

- **Last reviewed**: 13/07/2026

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Social

- Chat on [Matrix](https://matrix.to/#/#pimalaya:matrix.org)
- News on [Mastodon](https://fosstodon.org/@pimalaya) or [RSS](https://fosstodon.org/@pimalaya.rss)
- Mail at [pimalaya.org@posteo.net](mailto:pimalaya.org@posteo.net)

## Sponsoring

[![nlnet](https://nlnet.nl/logo/banner-160x60.png)](https://nlnet.nl/)

Special thanks to the [NLnet foundation](https://nlnet.nl/) and the [European Commission](https://www.ngi.eu/) that have been financially supporting the project for years:

- 2022 → 2023: [NGI Assure](https://nlnet.nl/project/Himalaya/)
- 2023 → 2024: [NGI Zero Entrust](https://nlnet.nl/project/Pimalaya/)
- 2024 → 2026: [NGI Zero Core](https://nlnet.nl/project/Pimalaya-PIM/)
- *2027 in preparation…*

If you appreciate the project, feel free to donate using one of the following providers:

[![GitHub](https://img.shields.io/badge/-GitHub%20Sponsors-fafbfc?logo=GitHub%20Sponsors)](https://github.com/sponsors/soywod)
[![Ko-fi](https://img.shields.io/badge/-Ko--fi-ff5e5a?logo=Ko-fi&logoColor=ffffff)](https://ko-fi.com/soywod)
[![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-ffdd00?logo=Buy%20Me%20A%20Coffee&logoColor=000000)](https://www.buymeacoffee.com/soywod)
[![Liberapay](https://img.shields.io/badge/-Liberapay-f6c915?logo=Liberapay&logoColor=222222)](https://liberapay.com/soywod)
[![thanks.dev](https://img.shields.io/badge/-thanks.dev-000000?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQuMDk3IiBoZWlnaHQ9IjE3LjU5NyIgY2xhc3M9InctMzYgbWwtMiBsZzpteC0wIHByaW50Om14LTAgcHJpbnQ6aW52ZXJ0IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik05Ljc4MyAxNy41OTdINy4zOThjLTEuMTY4IDAtMi4wOTItLjI5Ny0yLjc3My0uODktLjY4LS41OTMtMS4wMi0xLjQ2Mi0xLjAyLTIuNjA2di0xLjM0NmMwLTEuMDE4LS4yMjctMS43NS0uNjc4LTIuMTk1LS40NTItLjQ0Ni0xLjIzMi0uNjY5LTIuMzQtLjY2OUgwVjcuNzA1aC41ODdjMS4xMDggMCAxLjg4OC0uMjIyIDIuMzQtLjY2OC40NTEtLjQ0Ni42NzctMS4xNzcuNjc3LTIuMTk1VjMuNDk2YzAtMS4xNDQuMzQtMi4wMTMgMS4wMjEtMi42MDZDNS4zMDUuMjk3IDYuMjMgMCA3LjM5OCAwaDIuMzg1djEuOTg3aC0uOTg1Yy0uMzYxIDAtLjY4OC4wMjctLjk4LjA4MmExLjcxOSAxLjcxOSAwIDAgMC0uNzM2LjMwN2MtLjIwNS4xNTYtLjM1OC4zODQtLjQ2LjY4Mi0uMTAzLjI5OC0uMTU0LjY4Mi0uMTU0IDEuMTUxVjUuMjNjMCAuODY3LS4yNDkgMS41ODYtLjc0NSAyLjE1NS0uNDk3LjU2OS0xLjE1OCAxLjAwNC0xLjk4MyAxLjMwNXYuMjE3Yy44MjUuMyAxLjQ4Ni43MzYgMS45ODMgMS4zMDUuNDk2LjU3Ljc0NSAxLjI4Ny43NDUgMi4xNTR2MS4wMjFjMCAuNDcuMDUxLjg1NC4xNTMgMS4xNTIuMTAzLjI5OC4yNTYuNTI1LjQ2MS42ODIuMTkzLjE1Ny40MzcuMjYuNzMyLjMxMi4yOTUuMDUuNjIzLjA3Ni45ODQuMDc2aC45ODVabTE0LjMxNC03LjcwNmgtLjU4OGMtMS4xMDggMC0xLjg4OC4yMjMtMi4zNC42NjktLjQ1LjQ0Ni0uNjc3IDEuMTc3LS42NzcgMi4xOTVWMTQuMWMwIDEuMTQ0LS4zNCAyLjAxMy0xLjAyIDIuNjA2LS42OC41OTMtMS42MDUuODktMi43NzQuODloLTIuMzg0di0xLjk4OGguOTg0Yy4zNjIgMCAuNjg4LS4wMjcuOTgtLjA4LjI5Mi0uMDU1LjUzOC0uMTU3LjczNy0uMzA4LjIwNC0uMTU3LjM1OC0uMzg0LjQ2LS42ODIuMTAzLS4yOTguMTU0LS42ODIuMTU0LTEuMTUydi0xLjAyYzAtLjg2OC4yNDgtMS41ODYuNzQ1LTIuMTU1LjQ5Ny0uNTcgMS4xNTgtMS4wMDQgMS45ODMtMS4zMDV2LS4yMTdjLS44MjUtLjMwMS0xLjQ4Ni0uNzM2LTEuOTgzLTEuMzA1LS40OTctLjU3LS43NDUtMS4yODgtLjc0NS0yLjE1NXYtMS4wMmMwLS40Ny0uMDUxLS44NTQtLjE1NC0xLjE1Mi0uMTAyLS4yOTgtLjI1Ni0uNTI2LS40Ni0uNjgyYTEuNzE5IDEuNzE5IDAgMCAwLS43MzctLjMwNyA1LjM5NSA1LjM5NSAwIDAgMC0uOTgtLjA4MmgtLjk4NFYwaDIuMzg0YzEuMTY5IDAgMi4wOTMuMjk3IDIuNzc0Ljg5LjY4LjU5MyAxLjAyIDEuNDYyIDEuMDIgMi42MDZ2MS4zNDZjMCAxLjAxOC4yMjYgMS43NS42NzggMi4xOTUuNDUxLjQ0NiAxLjIzMS42NjggMi4zNC42NjhoLjU4N3oiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)](https://thanks.dev/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
