//! Module dedicated to the OAuth 2.0 Authorization Framework.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc6749>

pub mod authorization_code_grant;
#[cfg(feature = "client")]
pub mod client;
pub mod device_authorization_grant;
pub mod issue_access_token;
pub mod refresh_access_token;
pub mod rfc7591;
pub mod rfc8414;
pub mod rfc9728;
