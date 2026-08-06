//! JWT profile for OAuth 2.0 client authentication and authorization
//! grants (RFC 7523).
//!
//! The two JWT bearer exchanges enabling fully headless
//! machine-to-machine authentication: a signed JWT used as an
//! authorization grant of its own ([`crate::rfc7523::auth_grant`],
//! section 2.1, the Google service account flow), or as the client
//! authentication of the client credentials grant
//! ([`crate::rfc7523::client_auth`], section 2.2, the Microsoft
//! certificate credentials flow). The assertion format and its RS256
//! signing live in [`crate::rfc7523::assertion`] (section 3), with
//! the signing key behind the `jwt-bearer` feature since it pulls the
//! rsa and sha1 crates.

pub mod assertion;
pub mod auth_grant;
pub mod client_auth;
