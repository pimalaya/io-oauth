# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-13

### Added

- Added the OAuth 2.0 device authorization grant (RFC 8628) as the `rfc8628` module: the `Oauth20RequestDeviceAuth` and single-poll `Oauth20RequestDeviceAccessToken` coroutines, plus the `Oauth20ClientStd` device methods (`request_device_authorization`, `request_device_access_token`, and the TLS-gated `await_device_access_token` polling loop honoring `slow_down` and the code lifetime).
- Added the client credentials grant (RFC 6749 §4.4) as `rfc6749::client_credentials`: the `Oauth20RequestClientCredentials` coroutine and `Oauth20ClientStd::request_client_credentials`.
- Added dynamic client registration (RFC 7591) as `rfc7591::register`: the `Oauth20RegisterClient` coroutine, letting a public client register with `token_endpoint_auth_method: none` (no secret, no provider console). The paired metadata discovery (RFC 8414 / 9728) lives in [io-pim-discovery](https://github.com/pimalaya/io-pim-discovery), not here.
- Added the std-blocking `Oauth20ClientStd` behind the new `client` feature: a light client wrapping any `Read + Write + Send` stream, or a full client opening the TCP/TLS connection itself (behind the `native-tls`, `rustls-aws` and `rustls-ring` features). Ships the `await_redirect` helper for the loopback authorization redirect.
- Added the optional `client_secret` field to the access-token and refresh params (Google requires it even for installed apps that cannot keep it confidential).
- Added `extras` on the authorization request for provider-specific query parameters, `Oauth20AuthParams::validate` for CSRF-checked code extraction, and `parse_http_date` for the HTTP `Date` header.
- Added the RFC 8707 `invalid_target` error code and a catch-all `Unknown` variant to the OAuth error enums, so an unregistered code is no longer masked as `InvalidRequest`.

### Changed

- Made the crate `no_std`: `alloc` by default, `std` and the random `Oauth20State` / `Oauth20PkceCodeVerifier` constructors pulled by the `client` feature.
- Migrated every coroutine from io-stream to the io-http (RFC 9110 / 9112) API: `new` is no longer fallible, `resume` takes `Option<&[u8]>` and yields `WantsRead` / `WantsWrite`, and an unexpected redirect surfaces as a `Redirect` error.
- Reorganised the source tree by RFC, one folder per RFC like io-http: OAuth 2.0 is `rfc6749`, PKCE `rfc7636`, the device grant `rfc8628`, registration `rfc7591`. Public paths are now `io_oauth::rfc6749::…` (and `rfc7636` / `rfc8628` / `rfc7591`).
- Renamed every public type to carry the `Oauth20` version prefix and follow `<Verb><Target>` order (e.g. `RequestOauth2AccessToken` is now `Oauth20RequestAccessToken`, `State` is now `Oauth20State`, `PkceCodeChallenge` is now `Oauth20PkceCodeChallenge`); the `authorization_pending` and `authorization_declined` wire codes keep their spelling.
- Changed `Oauth20IssueAccessTokenSuccessParams::issued_at` from `SystemTime` to optional Unix epoch seconds populated from the HTTP `Date` header, and removed `sync_expires_in`.
- Changed scope collections from `HashSet` to `BTreeSet`, and build the authorization URL through `build_url` (preserving query parameters already present in the endpoint).
- Made the crate-level rustdoc (`lib.rs`) the architecture document.

### Removed

- Removed the `oauth2`, `rfc6749`, `pkce` and `rfc7636` cargo features: OAuth 2.0 and PKCE are now always compiled.

## [0.0.4] - 2026-02-12

### Changed

- Bumped sha2@0.11-rc5 and rand@0.10

## [0.0.3] - 2025-10-24

### Changed

- Bumped all dependencies

## [0.0.2] - 2025-09-11

### Changed

- Cleaned the whole lib

## [0.0.1] - 2025-06-04

### Added

- Added OAuth 2.0 module with authorization code grant flow

[unreleased]: https://github.com/pimalaya/io-oauth/compare/v0.1.0..master
[0.1.0]: https://github.com/pimalaya/io-oauth/compare/v0.0.4..v0.1.0
[0.0.4]: https://github.com/pimalaya/io-oauth/compare/v0.0.3..v0.0.4
[0.0.3]: https://github.com/pimalaya/io-oauth/compare/v0.0.2..v0.0.3
[0.0.2]: https://github.com/pimalaya/io-oauth/compare/v0.0.1..v0.0.2
[0.0.1]: https://github.com/pimalaya/io-oauth/compare/root..v0.0.1
