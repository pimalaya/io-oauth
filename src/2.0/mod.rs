//! Module dedicated to the OAuth 2.0 Authorization Framework.
//!
//! Refs: https://datatracker.ietf.org/doc/html/rfc6749

#[path = "authorization-code-grant/mod.rs"]
pub mod authorization_code_grant;
#[path = "issue-access-token.rs"]
pub mod issue_access_token;
#[path = "refresh-access-token.rs"]
pub mod refresh_access_token;

#[doc(inline)]
pub use self::{
    issue_access_token::{
        AccessTokenResponse, IssueAccessTokenErrorCode, IssueAccessTokenErrorParams,
        IssueAccessTokenSuccessParams,
    },
    refresh_access_token::{RefreshAccessToken, RefreshAccessTokenParams},
};
