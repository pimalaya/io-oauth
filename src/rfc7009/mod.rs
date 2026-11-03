//! OAuth 2.0 Token Revocation (RFC 7009).
//!
//! Tells the authorization server a token is no longer needed, so it
//! invalidates the token and, for a refresh token, the grant behind it.

pub mod revoke;
