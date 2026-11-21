//! OAuth 2.0 Authorization Framework (RFC 6749).
//!
//! The authorization code grant, the client credentials grant, and
//! the token issuance and refresh exchanges shared by every grant.

#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod access_token_request;
pub mod auth_request;
pub mod auth_response;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod client_credentials;
pub mod issue_access_token;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod refresh_access_token;
pub mod state;
