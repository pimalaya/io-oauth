//! Module dedicated to the section 4.1.2: Authorization Response.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2>

use alloc::borrow::Cow;

use log::debug;
use serde::{
    Deserialize, Serialize,
    de::value::{CowStrDeserializer, Error},
};
use thiserror::Error as ThisError;
use url::Url;

use crate::v2_0::authorization_code_grant::state::Oauth20State;

pub enum Oauth20AuthorizeParams<'a> {
    Success(Oauth20AuthorizeSuccessParams<'a>),
    Error(Oauth20AuthorizeErrorParams<'a>),
}

impl<'a> Oauth20AuthorizeParams<'a> {
    /// Validate the authorization response and return the authorization
    /// code on success.
    ///
    /// When `expected_state` is `Some`, the response must carry a
    /// matching state (CSRF protection per RFC 6749 §10.12); when
    /// `None`, the state field is not checked.
    pub fn validate(
        self,
        expected_state: Option<&Oauth20State>,
    ) -> Result<Cow<'a, str>, Oauth20AuthorizeValidateError<'a>> {
        match self {
            Self::Error(err) => Err(Oauth20AuthorizeValidateError::Server(err)),
            Self::Success(success) => {
                if let Some(expected) = expected_state {
                    match &success.state {
                        None => return Err(Oauth20AuthorizeValidateError::StateMissing),
                        Some(got) if expected != got.as_ref() => {
                            return Err(Oauth20AuthorizeValidateError::StateMismatch);
                        }
                        Some(_) => {}
                    }
                }
                Ok(success.code)
            }
        }
    }
}

/// Errors returned by [`Oauth20AuthorizeParams::validate`].
#[derive(Debug, ThisError)]
pub enum Oauth20AuthorizeValidateError<'a> {
    /// The authorization server returned an error response.
    #[error("Authorization error: {:?}", _0.error)]
    Server(Oauth20AuthorizeErrorParams<'a>),
    /// A state was expected in the response but none was returned.
    #[error("Authorization state missing from response")]
    StateMissing,
    /// The state returned by the server does not match the expected
    /// one (CSRF mismatch).
    #[error("Authorization state mismatch")]
    StateMismatch,
}

impl<'a> From<&'a Url> for Oauth20AuthorizeParams<'a> {
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
                    match Oauth20AuthorizeErrorCode::deserialize(deserializer) {
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
            let params = Oauth20AuthorizeSuccessParams { code, state };
            return Oauth20AuthorizeParams::Success(params);
        }

        let params = Oauth20AuthorizeErrorParams {
            error: error.unwrap_or(Oauth20AuthorizeErrorCode::InvalidRequest),
            error_description,
            error_uri,
        };

        Oauth20AuthorizeParams::Error(params)
    }
}

/// The authorization response parameters from the authorization code
/// grant.
///
/// If the resource owner grants the access request, the authorization
/// server issues an authorization code and delivers it to the client
/// by adding the following parameters to the query component of the
/// redirection URI using the "application/x-www-form-urlencoded"
/// format, per Appendix B.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20AuthorizeSuccessParams<'a> {
    /// The authorization code generated by the authorization server.
    ///
    /// The authorization code MUST expire shortly after it is issued
    /// to mitigate the risk of leaks.  A maximum authorization code
    /// lifetime of 10 minutes is RECOMMENDED.  The client MUST NOT
    /// use the authorization code more than once.  If an
    /// authorization code is used more than once, the authorization
    /// server MUST deny the request and SHOULD revoke (when possible)
    /// all tokens previously issued based on that authorization code.
    /// The authorization code is bound to the client identifier and
    /// redirection URI.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2>
    pub code: Cow<'a, str>,

    /// An opaque value used by the client to maintain state between
    /// the request and callback.
    ///
    /// The authorization server includes this value when redirecting
    /// the user-agent back to the client.  The parameter SHOULD be
    /// used for preventing cross-site request forgery.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
    pub state: Option<Cow<'a, Oauth20State>>,
}

/// The response returned by the authorization server when the the
/// resource owner denies the access request or if the request fails
/// for reasons other than a missing or invalid redirection URI.
///
/// The authorization server informs the client by adding the
/// following parameters to the query component of the redirection URI
/// using the "application/x-www-form-urlencoded" format.
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20AuthorizeErrorParams<'a> {
    /// A single ASCII error code.
    pub error: Oauth20AuthorizeErrorCode,

    /// Human-readable ASCII text providing additional information,
    /// used to assist the client developer in understanding the error
    /// that occurred.
    pub error_description: Option<Cow<'a, str>>,

    /// A URI identifying a human-readable web page with information
    /// about the error, used to provide the client developer with
    /// additional information about the error.
    pub error_uri: Option<Cow<'a, Url>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oauth20AuthorizeErrorCode {
    /// The request is missing a required parameter, includes an
    /// invalid parameter value, includes a parameter more than once,
    /// or is otherwise malformed.
    InvalidRequest,

    /// The client is not authorized to request an authorization code
    /// using this method.
    UnauthorizedClient,

    /// The resource owner or authorization server denied the request.
    AccessDenied,

    /// The authorization server does not support obtaining an
    /// authorization code using this method.
    UnsupportedResponseType,

    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,

    /// The authorization server encountered an unexpected condition
    /// that prevented it from fulfilling the request. (This error
    /// code is needed because a 500 Internal Server Error HTTP status
    /// code cannot be returned to the client via an HTTP redirect.)
    ServerError,

    /// The authorization server is currently unable to handle the
    /// request due to a temporary overloading or maintenance of the
    /// server.  (This error code is needed because a 503 Service
    /// Unavailable HTTP status code cannot be returned to the client
    /// via an HTTP redirect.)
    TemporarilyUnavailable,
}
