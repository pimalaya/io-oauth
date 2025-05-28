//! Module dedicated to the section 4.1: Authorization Code Grant.
//!
//! Refs: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1

#[path = "access-token-request.rs"]
pub mod access_token_request;
#[path = "authorization-request.rs"]
pub mod authorization_request;
#[path = "authorization-response.rs"]
pub mod authorization_response;
#[cfg(feature = "pkce")]
pub mod pkce;
pub mod state;
