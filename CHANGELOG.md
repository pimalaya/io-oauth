# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `rfc8628::auth::Oauth20DeviceAuthSuccessParams::lifetime`, the device code lifetime capped at one hour.
- Added `rfc8628::auth::Oauth20DeviceAuthSuccessParams::poll_interval`, the polling interval kept between 1 and 60 seconds.
- Added `rfc6749::state::Oauth20State::from_entropy`, building a state from 32 random bytes of the caller.
- Added `rfc7636::pkce::Oauth20PkceCodeVerifier::from_entropy`, building a verifier from 32 random bytes of the caller (RFC 7636 section 4.1).
- Added `TryFrom<&[u8]>` for `rfc6749::state::Oauth20State`, failing with `Oauth20StateError`.
- Added `TryFrom<&[u8]>` for `rfc7636::pkce::Oauth20PkceCodeVerifier`, failing with `Oauth20PkceCodeVerifierError`.
- Added `to_body` to the request params of `rfc6749::access_token_request`, `rfc6749::refresh_access_token`, `rfc7009::revoke`, `rfc7523::auth_grant`, `rfc7523::client_auth` and `rfc8628::token`, building the form body.

### Changed

- **BREAKING**: Changed `client::await_redirect` and `client::await_redirect_on` to take the expected state and to wait for the authorization redirect only.

  The wait ends on a `GET` to the redirect path carrying a `code` or an `error`, and echoing the state when one is given. Any other connection is answered `404 Not Found` and dropped, after at most 5 seconds and an 8 KiB request line. The `200 OK` page no longer claims a success.

- **BREAKING**: Changed `rfc6749::auth_response::Oauth20AuthParams::validate` to take the expected issuer (RFC 9207).

  A code from a response naming another issuer fails with the new `Oauth20AuthParamsValidationError::IssuerMismatch`. `Oauth20AuthSuccessParams` carries the `iss` parameter.

- **BREAKING**: Changed a non-success status without an OAuth error body to end in a new `Status(u16)` error, in the access token, refresh, client credentials, device, JWT bearer and registration coroutines.

  It ended in `ParseHttpResponse`, the status lost.

- **BREAKING**: Changed `expires_in` of `rfc6749::issue_access_token::Oauth20AccessTokenSuccessParams` to `Option<u64>`, read from a number or from a numeric string.
- Changed `token_type` of `rfc6749::issue_access_token::Oauth20AccessTokenSuccessParams` to default to `Bearer` when the server sends none.
- **BREAKING**: Changed `FromStr` for `rfc7636::pkce::Oauth20PkceCodeVerifier` to refuse a verifier outside 43 to 128 characters.

  Its error is `Oauth20PkceCodeVerifierError` instead of the offending byte.

- Changed `rfc6749::state::Oauth20State` generation to the unreserved characters.

  An empty state no longer deserializes.

### Removed

- **BREAKING**: Removed `client::Oauth20ClientStdError::InvalidRedirectRequest`.

  A malformed request no longer ends the wait on the redirect.

- **BREAKING**: Removed `Display` from the request params carrying a secret, the six that gained `to_body`.

### Fixed

- Fixed `client::Oauth20ClientStd::await_device_access_token` panicking or sleeping without end on a server-chosen `expires_in` or `interval`.

  Both are bounded, and no sleep outlasts the device code lifetime.

- Fixed `rfc6749::issue_access_token::parse_http_date` overflowing on a day zero or a date before 1970.

  It returns `None`, where a release build returned a wrapped date.

- Fixed `client::Oauth20ClientStd` sending the client id and secret of its Basic credentials without the form encoding of RFC 6749 section 2.3.1.

  Letters, digits and `*-._~` stay literal, `~` included although the form encoding escapes it: a server comparing the raw credentials only knows the literal one. An id or a secret made of these characters is unchanged on the wire.

- Fixed `Debug` on `rfc6749::access_token_request::Oauth20AccessTokenRequest` printing the pending request, code and client secret included.

## [0.5.2] - 2026-11-11

### Changed

- Replaced rand with [getrandom](https://crates.io/crates/getrandom) for the state and PKCE code verifier generation.

  The `client` feature no longer pulls rand, rand_core and chacha20.

- Bumped rsa to 0.10.0, its first stable release, outside the RUSTSEC-2023-0071 range the release candidates fell in (the `jwt-bearer` feature).

### Fixed

- Fixed `rfc6749::state::Oauth20State` and `rfc7636::pkce::Oauth20PkceCodeVerifier` generation never repeating a character.

  Each character is now drawn independently, so `new` honours sizes above the alphabet length: `Oauth20PkceCodeVerifier::new(128)` held 66 characters, `Oauth20State::new` stopped at 95.

## [0.5.1] - 2026-11-04

### Added

- Added `client::await_redirect_on`, accepting the authorization redirect on a listener the caller bound.

## [0.5.0] - 2026-11-04

### Added

- Added `rfc7009::revoke`, the RFC 7009 token revocation coroutine.
- Added `client::Oauth20ClientStd::revoke_token`.

### Changed

- **BREAKING**: Changed `rfc6749::auth_request::Oauth20AuthRequestParams` to carry `resource`, the RFC 8707 resource indicators.

  Each entry is one `resource` parameter. A `resource` extra or endpoint parameter replaces them.

- **BREAKING**: Changed `rfc6749::access_token_request::Oauth20AccessTokenRequestParams` to carry `resource`, the RFC 8707 resource indicators.

## [0.4.1] - 2026-11-03

### Changed

- Replaced the base64 crate with [base64-codec](https://crates.io/crates/base64-codec) for the PKCE challenge and the JWT bearer assertion.

  It runs on the CPU token the application installs with `simd_cpu::SimdCpu::install_detected`, the portable baseline when none is.

### Security

- Raised the pimalaya-stream requirement to 0.3.1, fixing RUSTSEC-2026-0346 to RUSTSEC-2026-0349.

  It requires rustls 0.23.46.

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

[unreleased]: https://github.com/pimalaya/io-oauth/compare/v0.5.2..HEAD
[0.5.2]: https://github.com/pimalaya/io-oauth/compare/v0.5.1..v0.5.2
[0.5.1]: https://github.com/pimalaya/io-oauth/compare/v0.5.0..v0.5.1
[0.5.0]: https://github.com/pimalaya/io-oauth/compare/v0.4.1..v0.5.0
[0.4.1]: https://github.com/pimalaya/io-oauth/compare/v0.4.0..v0.4.1
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
