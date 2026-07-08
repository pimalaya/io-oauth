# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the discovery and registration chain of draft-ietf-mailmaint-oauth-public, three RFC-dedicated modules under v2_0:

  - rfc8414::server_metadata: the `Oauth20ServerMetadata` document (endpoints, grants, PKCE methods, the RFC 7591 registration endpoint) with its `Oauth20FetchServerMetadata` coroutine, plus the well-known URL builders (the §3.1 insertion rule and the OpenID Connect Discovery compatibility suffix).
  - rfc9728::resource_metadata: the `Oauth20ResourceMetadata` document (authorization servers, scopes, bearer methods) with its `Oauth20FetchResourceMetadata` coroutine, the well-known URL builder, and `challenge_resource_metadata` extracting the metadata URL a protected resource advertises on its 401 `WWW-Authenticate`.
  - rfc7591::client_registration: the `Oauth20RegisterClient` coroutine POSTing `Oauth20RegisterClientParams` to the registration endpoint and returning the issued `Oauth20ClientInformation` or the §3.2.2 error params; a public client registers with `token_endpoint_auth_method: none` and needs no secret nor any provider console.

  Together they let a client go from an unauthenticated 401 to a usable client id with zero pre-registration (fastmail implements the whole chain); Google and Microsoft publish no registration endpoint, so their console-issued client ids remain required there.

- Added the optional `client_secret` field to `Oauth20AccessTokenRequestParams` and `Oauth20RefreshAccessTokenParams`, serialized into the form body when set; Google requires the secret in both exchanges for its desktop-type clients, even though such installed apps cannot keep it confidential.

- Added the OAuth 2.0 Device Authorization Grant (RFC 8628) as the device_authorization_grant module, with the `Oauth20RequestDeviceAuthorization` coroutine (device and user code request) and the single-poll `Oauth20RequestDeviceAccessToken` coroutine; `Oauth20IssueAccessTokenErrorCode` gained the RFC 8628 §3.5 codes, the non-standard Microsoft Entra `authorization_declined` and `bad_verification_code` codes, plus a catch-all `Unknown` variant
- Added device flow methods to `Oauth20ClientStd`: `request_device_authorization`, single-poll `request_device_access_token` and the TLS-gated `await_device_access_token` polling loop (sleeps the interval, honors `slow_down`, reconnects per attempt, stops on the device code lifetime)
- Added std-blocking client module behind the new `client` cargo feature, with `Oauth20ClientStd` (wraps any stream, or connects itself via the new `native-tls`, `rustls-aws` and `rustls-ring` cargo features) and the `await_redirect` helper listening for the authorization redirect on a local TCP socket
- Added `extras` field to `Oauth20AuthorizationRequestParams` for provider-specific authorization query parameters
- Added `Oauth20AuthorizeParams::validate` checking the CSRF state and returning the authorization code
- Added `parse_http_date` parsing HTTP IMF-fixdate strings into Unix epoch seconds

### Changed

- Renamed all public types with the version-scoped `Oauth20` prefix, following the io-http `Http11` convention: `RequestOauth2AccessToken` is now `Oauth20RequestAccessToken`, `RefreshOauth2AccessToken` is now `Oauth20RefreshAccessToken`, `AuthorizeParams` is now `Oauth20AuthorizeParams`, `State` is now `Oauth20State`, `PkceCodeChallenge` is now `Oauth20PkceCodeChallenge`, and so on
- Made the crate `no_std`: `alloc`-based by default, `std` pulled by the `client` cargo feature
- Removed the `oauth2`, `rfc6749`, `pkce` and `rfc7636` cargo features, OAuth 2.0 and PKCE support are now always compiled
- Migrated coroutines from io-stream to the io-http rfc9110/rfc9112 API: `new` is no longer fallible, `resume` takes `Option<&[u8]>` and yields `WantsRead`/`WantsWrite`, unexpected redirections surface as a dedicated `Redirect` error variant
- Changed `Oauth20IssueAccessTokenSuccessParams::issued_at` from `SystemTime` to optional Unix epoch seconds, populated by the coroutines from the HTTP Date response header; removed `sync_expires_in`
- Replaced `Oauth20AuthorizationRequestParams::to_form_url_encoded_serializer` and `to_form_url_encoded_string` with `build_url`, which preserves query parameters already present in the endpoint URL
- Replaced `ToString` impls on request params with `fmt::Display`
- Changed scopes collections from `HashSet` to `BTreeSet`
- Gated random generators (`Oauth20State`/`Oauth20PkceCodeVerifier` constructors and `Default` impls) behind the `client` cargo feature, making rand an optional dependency

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

[unreleased]: https://github.com/pimalaya/io-oauth/compare/v0.0.4..master
[0.0.4]: https://github.com/pimalaya/io-oauth/compare/v0.0.3..v0.0.4
[0.0.3]: https://github.com/pimalaya/io-oauth/compare/v0.0.2..v0.0.3
[0.0.2]: https://github.com/pimalaya/io-oauth/compare/v0.0.1..v0.0.2
[0.0.1]: https://github.com/pimalaya/io-oauth/compare/root..v0.0.1
