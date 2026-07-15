#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # io-oauth
//!
//! I/O-free OAuth coroutines built on [io-http]. Every network
//! exchange is a resumable state machine that emits read and write
//! requests instead of performing I/O itself: the caller owns the
//! socket and pumps the coroutine with the bytes it read, whatever
//! the runtime (blocking, async, in-memory tests). The `client`
//! feature ships a ready-made std-blocking pump for callers who just
//! want a working client.
//!
//! [io-http]: https://docs.rs/io-http
//!
//! ## Layout: one folder per RFC
//!
//! io-oauth covers OAuth in general; today only OAuth 2.0 is
//! implemented. The source tree is organised by RFC, mirroring
//! io-http, so the RFC number is the version discriminator (no `2.x`
//! wrapper). A future OAuth 2.1 (largely a consolidation of RFC 6749,
//! 6750 and 7636 with mandatory PKCE and the deprecated grants
//! removed) would slot in as its own RFC modules alongside the
//! existing ones.
//!
//! [`rfc6749`] holds the OAuth 2.0 Authorization Framework: the
//! authorization code grant through [`rfc6749::auth_request`],
//! [`rfc6749::auth_response`], [`rfc6749::access_token_request`] and
//! [`rfc6749::state`] (the section 10.12 CSRF value); the client
//! credentials grant through [`rfc6749::client_credentials`]; and the
//! token issuance and refresh exchanges shared by every grant through
//! [`rfc6749::issue_access_token`] and
//! [`rfc6749::refresh_access_token`].
//!
//! Around it, [`rfc7636`] provides PKCE ([`rfc7636::pkce`]), consumed
//! by the authorization code grant; [`rfc8628`] the device
//! authorization grant, with the device and user code request in
//! [`rfc8628::auth`] and the token endpoint polling in
//! [`rfc8628::token`]; and [`rfc7591`] dynamic client registration
//! ([`rfc7591::register`]), plus the preference order between the
//! ways a client obtains its registration ([`rfc7591::source`]).
//!
//! The optional [`client`] module (`client` feature) is the
//! std-blocking [`client::Oauth20ClientStd`] pump: a light client
//! wrapping any stream you opened yourself, or a full client opening
//! the TCP/TLS connection itself when one of the TLS features is
//! enabled. It spans the RFC modules (token operations, device grant,
//! dynamic client registration), which is why it lives at the crate
//! root rather than under one of them; a future OAuth version would
//! add its own client alongside, unified behind a version-agnostic
//! wrapper only once one exists.
//!
//! ## Intentional omissions
//!
//! The implicit grant (section 4.2) and the resource owner password
//! credentials grant (section 4.3) are removed by OAuth 2.1 and the
//! OAuth Security BCP (RFC 9700); they are deliberately not
//! implemented. Extension grants (section 4.5) are a
//! `grant_type=<URI>` mechanism, not a concrete flow, so there is
//! nothing generic to ship. Accessing protected resources (section 7)
//! means sending the issued bearer token on each request, which is
//! RFC 6750 and lives in io-http, not here: io-oauth issues the
//! token, the consumer uses it.
//!
//! ## Discovery lives elsewhere
//!
//! Fetching a provider's OAuth metadata (RFC 8414 authorization
//! server metadata, RFC 9728 protected resource metadata) is
//! discovery, not an OAuth action, and lives in [io-pim-discovery]. A
//! consumer discovers the token and registration endpoints there,
//! then runs the grants and registration here.
//!
//! [io-pim-discovery]: https://github.com/pimalaya/io-pim-discovery
//!
//! ## Conventions
//!
//! The crate is no_std with alloc; std only enters behind the
//! `client` feature. Every public type carries the version-scoped
//! `Oauth20` prefix (mirroring io-http's `Http11`), reading from the
//! largest scope down to the narrowest: [`rfc8628::auth`] exposes
//! `Oauth20DeviceAuthRequest`, never a bare `DeviceAuthRequest`. Each
//! coroutine exposes `new` plus `resume(Option<&[u8]>)` returning a
//! `Result`-suffixed enum that yields `WantsRead` and `WantsWrite`,
//! and surfaces an unexpected 3xx as a `Redirect` error. RFC wire
//! tokens are never renamed: the `authorization_pending` and
//! `authorization_declined` error codes keep their spelling even
//! though identifiers otherwise shorten authorization to auth.

extern crate alloc;
#[cfg(feature = "client")]
extern crate std;

#[cfg(feature = "client")]
pub mod client;
pub mod rfc6749;
pub mod rfc7591;
pub mod rfc7636;
pub mod rfc8628;
