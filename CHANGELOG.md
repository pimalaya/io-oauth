# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-11-03

### Changed

- **BREAKING**: Bumped io-http to 0.6.

  The coroutines take and yield its types, so consumers bump it in step. A token response over 64 KiB of head or 256 MiB of body now fails with `SendHttpRequest`.

- Raised the minimum supported Rust version from 1.88 to 1.89.

## [0.3.1] - 2026-11-03

### Changed

- Bumped rsa to 0.10.0-rc.20.

  Its error types surface in `Oauth20JwtBearerKeyError`, behind the `jwt-bearer` feature.

### Removed

- Removed the docs/ folder, replaced by cairn/.

## [0.3.0] - 2026-08-15

### Changed

- Bumped io-http to 0.5.

  The coroutines take and yield its types, so consumers bump it in step.

- Bumped pimalaya-stream to 0.3.

  Its `Read` and `Write` retry a stream reporting `EAGAIN` for up to a minute before failing with `TimedOut`, and connects arm a socket read deadline. Its `StreamStd` is renamed `stream::Stream`.

## [0.2.3] - 2026-08-15

### Changed

- Bumped io-http to 0.4.

  The coroutines take and yield its types, so consumers bump it in step.

## [0.2.2] - 2026-08-15

### Changed

- Bumped pimalaya-stream to 0.2.
- Raised the minimum supported Rust version from 1.87 to 1.88.

## [0.2.1] - 2026-08-06

### Added

- Added the RFC 7523 `rfc7523::auth_grant::Oauth20JwtBearerGrantRequest` coroutine.

  The JWT bearer authorization grant (section 2.1), with user impersonation through the `sub` claim.

- Added the RFC 7523 `rfc7523::client_auth::Oauth20JwtBearerClientCredentialsRequest` coroutine.

  The client credentials grant authenticated by a signed `client_assertion` (section 2.2).

- Added `rfc7523::assertion::Oauth20JwtBearerClaims`, a clock-free JWT claim set.
- Added `rfc7523::assertion::Oauth20JwtBearerKey`, an RS256 signing key read from PKCS#8 or PKCS#1, PEM or DER.
- Added the `rfc7523::assertion::x5t_from_der` certificate thumbprint helper.
- Added the `jwt-bearer` cargo feature, gating the signing key and the thumbprint helper.
- Added `Oauth20ClientStd::request_jwt_bearer_grant` and `Oauth20ClientStd::request_jwt_bearer_client_credentials`.
- Added `Oauth20ClientStd::sign_jwt_bearer_assertion`, behind the `jwt-bearer` feature.

  It defaults `aud` to the token endpoint and `iat` and `exp` to the system clock.

- Added the `jwt_bearer_client_credentials` example.

### Changed

- Bumped base64 to 0.23.
- Lowered the minimum supported Rust version to 1.87.

## [0.2.0] - 2026-07-15

### Added

- Added `rfc7591::source::Oauth20ClientSource`, the ways a client obtains its registration, in preference order.
- Added `Oauth20ClientStd::register_client`.

### Changed

- Moved `Oauth20ClientStd` and `await_redirect` from `rfc6749::client` to the crate-root `client` module.
- Renamed `Oauth20RequestAccessToken*` to `Oauth20AccessTokenRequest*`.
- Renamed `Oauth20RefreshAccessToken*` to `Oauth20AccessTokenRefresh*`.
- Renamed `Oauth20RequestClientCredentials*` to `Oauth20ClientCredentialsRequest*`.
- Renamed `Oauth20RequestDeviceAuth*` to `Oauth20DeviceAuthRequest*`.
- Renamed `Oauth20RequestDeviceAccessToken*` to `Oauth20DeviceAccessTokenRequest*`.
- Renamed `Oauth20RegisterClient*` to `Oauth20ClientRegister*`.
- Renamed `Oauth20IssueAccessTokenSuccessParams` to `Oauth20AccessTokenSuccessParams`.
- Renamed `Oauth20IssueAccessTokenErrorParams` to `Oauth20AccessTokenErrorParams`.
- Renamed `Oauth20IssueAccessTokenErrorCode` to `Oauth20AccessTokenErrorCode`.
- Renamed `Oauth20ClientStd::request_device_authorization` to `Oauth20ClientStd::request_device_auth`.
- Renamed the `Oauth20ClientStdError` variants after the renamed coroutines.
- Changed `Oauth20ClientStdError::UrlUnsupportedScheme` to a struct variant with `url` and `scheme` fields.
- Renamed the examples to snake_case: `auth_code_grant` and `device_auth_grant`.
- Bumped io-http to 0.3.
- Bumped pimalaya-stream to 0.1.

## [0.1.0] - 2026-07-13

### Added

- Added the RFC 8628 `Oauth20RequestDeviceAuth` and `Oauth20RequestDeviceAccessToken` coroutines.
- Added `Oauth20ClientStd::request_device_authorization` and `Oauth20ClientStd::request_device_access_token`.
- Added `Oauth20ClientStd::await_device_access_token`, polling until a token is issued.

  It honors `slow_down` and the device code lifetime.

- Added the RFC 6749 `Oauth20RequestClientCredentials` coroutine.
- Added `Oauth20ClientStd::request_client_credentials`.
- Added the RFC 7591 `Oauth20RegisterClient` coroutine.

  A public client registers with `token_endpoint_auth_method: none`, so no secret is needed.

- Added the blocking `Oauth20ClientStd`, behind the new `client` feature.

  It wraps any `Read + Write + Send` stream, or opens the TCP and TLS connection itself behind `native-tls`, `rustls-aws` or `rustls-ring`.

- Added the `await_redirect` helper for the loopback authorization redirect.
- Added the optional `client_secret` field to the access token and refresh params.
- Added `extras` to the authorization request, for extra query parameters.
- Added `Oauth20AuthParams::validate`, extracting the code after a CSRF check.
- Added `parse_http_date` for the HTTP `Date` header.
- Added the `invalid_target` and `Unknown` variants to the OAuth error code enums.

  An unregistered code no longer reads as `InvalidRequest`.

### Changed

- Made the crate `no_std`.

  It needs `alloc` only. `std` and the random `Oauth20State` and `Oauth20PkceCodeVerifier` constructors come with the `client` feature.

- Migrated every coroutine from io-stream to io-http.

  `new` is infallible, `resume` takes `Option<&[u8]>` and yields `WantsRead` or `WantsWrite`, and an unexpected redirect fails with `Redirect`.

- Reorganised the modules by RFC: `rfc6749`, `rfc7636`, `rfc8628` and `rfc7591`.
- Renamed every public type with the `Oauth20` prefix and the `<Verb><Target>` order.

  For example `RequestOauth2AccessToken` is now `Oauth20RequestAccessToken` and `State` is now `Oauth20State`.

- Changed `Oauth20IssueAccessTokenSuccessParams::issued_at` from `SystemTime` to optional Unix epoch seconds, read from the HTTP `Date` header.
- Changed scope collections from `HashSet` to `BTreeSet`.
- Changed the authorization URL to keep the query parameters already present in the endpoint.
- Made the crate-level rustdoc the architecture document.

### Removed

- Removed `sync_expires_in`.
- Removed the `oauth2`, `rfc6749`, `pkce` and `rfc7636` cargo features, OAuth 2.0 and PKCE being always compiled.

## [0.0.4] - 2026-02-12

### Changed

- Bumped sha2 to 0.11.0-rc.5.
- Bumped rand to 0.10.

## [0.0.3] - 2025-10-24

### Changed

- Bumped all dependencies.

## [0.0.2] - 2025-09-11

### Changed

- Cleaned the whole library.

## [0.0.1] - 2025-06-04

### Added

- Added the OAuth 2.0 authorization code grant.

[unreleased]: https://github.com/pimalaya/io-oauth/compare/v0.4.0..HEAD
[0.4.0]: https://github.com/pimalaya/io-oauth/compare/v0.3.1..v0.4.0
[0.3.1]: https://github.com/pimalaya/io-oauth/compare/v0.3.0..v0.3.1
[0.3.0]: https://github.com/pimalaya/io-oauth/compare/v0.2.3..v0.3.0
[0.2.3]: https://github.com/pimalaya/io-oauth/compare/v0.2.2..v0.2.3
[0.2.2]: https://github.com/pimalaya/io-oauth/compare/v0.2.1..v0.2.2
[0.2.1]: https://github.com/pimalaya/io-oauth/compare/v0.2.0..v0.2.1
[0.2.0]: https://github.com/pimalaya/io-oauth/compare/v0.1.0..v0.2.0
[0.1.0]: https://github.com/pimalaya/io-oauth/compare/v0.0.4..v0.1.0
[0.0.4]: https://github.com/pimalaya/io-oauth/compare/v0.0.3..v0.0.4
[0.0.3]: https://github.com/pimalaya/io-oauth/compare/v0.0.2..v0.0.3
[0.0.2]: https://github.com/pimalaya/io-oauth/compare/v0.0.1..v0.0.2
[0.0.1]: https://github.com/pimalaya/io-oauth/compare/root..v0.0.1
