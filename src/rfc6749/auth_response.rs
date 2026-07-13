//! Module dedicated to the section 4.1.2: Authorization Response.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2>

use core::fmt;

use alloc::borrow::Cow;

use log::debug;
use serde::{
    Deserialize, Serialize,
    de::value::{CowStrDeserializer, Error},
};
use thiserror::Error as ThisError;
use url::Url;

use crate::rfc6749::state::Oauth20State;

/// The parsed authorization response: an authorization code, or an error.
pub enum Oauth20AuthParams<'a> {
    /// The request succeeded, carrying the authorization code.
    Success(Oauth20AuthSuccessParams<'a>),
    /// The request was denied or failed.
    Error(Oauth20AuthErrorParams<'a>),
}

impl<'a> Oauth20AuthParams<'a> {
    /// Validates the response and returns the authorization code on success.
    ///
    /// When `expected_state` is `Some`, the response must carry a matching
    /// state (CSRF protection per RFC 6749 §10.12); when `None`, the state
    /// field is not checked.
    pub fn validate(
        self,
        expected_state: Option<&Oauth20State>,
    ) -> Result<Cow<'a, str>, Oauth20AuthParamsValidationError<'a>> {
        match self {
            Self::Error(err) => Err(Oauth20AuthParamsValidationError::Server(err)),
            Self::Success(success) => {
                if let Some(expected) = expected_state {
                    match &success.state {
                        None => return Err(Oauth20AuthParamsValidationError::StateMissing),
                        Some(got) if expected != got.as_ref() => {
                            return Err(Oauth20AuthParamsValidationError::StateMismatch);
                        }
                        Some(_) => {}
                    }
                }
                Ok(success.code)
            }
        }
    }
}

/// Errors returned by [`Oauth20AuthParams::validate`].
#[derive(Debug, ThisError)]
pub enum Oauth20AuthParamsValidationError<'a> {
    /// The authorization server returned an error response.
    #[error("Authorization error: {_0}")]
    Server(Oauth20AuthErrorParams<'a>),
    /// A state was expected in the response but none was returned.
    #[error("Authorization state missing from response")]
    StateMissing,
    /// The state returned by the server does not match the expected
    /// one (CSRF mismatch).
    #[error("Authorization state mismatch")]
    StateMismatch,
}

impl<'a> From<&'a Url> for Oauth20AuthParams<'a> {
    fn from(url: &'a Url) -> Self {
        let mut code = None;
        let mut state = None;

        let mut error = None;
        let mut error_description = None;
        let mut error_uri = None;

        for (key, val) in url.query_pairs() {
            match &key {
                key if key.eq_ignore_ascii_case("code") => {
                    code = Some(val);
                }
                key if key.eq_ignore_ascii_case("state") => {
                    let deserializer = CowStrDeserializer::<Error>::new(val);
                    match Oauth20State::deserialize(deserializer) {
                        Ok(valid_state) => state = Some(Cow::Owned(valid_state)),
                        Err(err) => debug!("skip invalid state: {err}"),
                    }
                }
                key if key.eq_ignore_ascii_case("error") => {
                    let deserializer = CowStrDeserializer::<Error>::new(val);
                    match Oauth20AuthErrorCode::deserialize(deserializer) {
                        Ok(code) => error = Some(code),
                        Err(err) => debug!("skip invalid error code: {err}"),
                    }
                }
                key if key.eq_ignore_ascii_case("error_description") => {
                    error_description = Some(val);
                }
                key if key.eq_ignore_ascii_case("error_uri") => {
                    let deserializer = CowStrDeserializer::<Error>::new(val);
                    match Url::deserialize(deserializer) {
                        Ok(uri) => error_uri = Some(Cow::Owned(uri)),
                        Err(err) => debug!("skip invalid error URI: {err}"),
                    }
                }
                _ => (),
            }
        }

        if let Some(code) = code {
            let params = Oauth20AuthSuccessParams { code, state };
            return Oauth20AuthParams::Success(params);
        }

        let params = Oauth20AuthErrorParams {
            error: error.unwrap_or(Oauth20AuthErrorCode::InvalidRequest),
            error_description,
            error_uri,
        };

        Oauth20AuthParams::Error(params)
    }
}

/// The successful authorization response, carrying the code (and state).
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20AuthSuccessParams<'a> {
    /// The authorization code to exchange for an access token.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2>
    pub code: Cow<'a, str>,
    /// The opaque CSRF value echoed by the server.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
    pub state: Option<Cow<'a, Oauth20State>>,
}

/// The error authorization response, when the request is denied or fails.
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20AuthErrorParams<'a> {
    /// A single ASCII error code.
    pub error: Oauth20AuthErrorCode,
    /// Human-readable text explaining the error.
    pub error_description: Option<Cow<'a, str>>,
    /// A URI to a human-readable page about the error.
    pub error_uri: Option<Cow<'a, Url>>,
}

impl fmt::Display for Oauth20AuthErrorParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.error)?;

        if let Some(description) = &self.error_description {
            write!(f, ": {description}")?;
        }

        Ok(())
    }
}

/// The error code of an authorization error response.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oauth20AuthErrorCode {
    /// The request is malformed or missing a required parameter.
    InvalidRequest,
    /// The client is not authorized to request a code this way.
    UnauthorizedClient,
    /// The resource owner or server denied the request.
    AccessDenied,
    /// The server does not support this response type.
    UnsupportedResponseType,
    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,
    /// The server hit an unexpected condition (redirect-safe 500).
    ServerError,
    /// The server is temporarily overloaded or down (redirect-safe 503).
    TemporarilyUnavailable,
    /// The `resource` parameter is invalid or missing (RFC 8707).
    ///
    /// Servers requiring an explicit `resource` (fastmail) answer this when
    /// the authorization request carries none.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8707#section-3>
    InvalidTarget,
    /// Any unregistered code, kept for provider-specific extensions.
    #[serde(other)]
    Unknown,
}
