//! Token revocation request and response (RFC 7009 section 2).
//!
//! Posts a token to the revocation endpoint advertised by the RFC 8414
//! server metadata. The server answers 200 whether or not the token was
//! valid, so success only means the token is unusable now.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_http::rfc9110::request::HttpRequest;
//! use io_oauth::rfc7009::revoke::*;
//! use url::Url;
//!
//! let revocation_url = Url::parse("https://example.com/revoke").unwrap();
//! let request = HttpRequest {
//!     method: "POST".into(),
//!     url: revocation_url.clone(),
//!     headers: Vec::new(),
//!     body: Vec::new(),
//! }
//! .header("Host", revocation_url.host_str().unwrap());
//!
//! let mut params = Oauth20TokenRevokeParams::new("client-id", "the-refresh-token");
//! params.token_type_hint = Some(Oauth20TokenTypeHint::RefreshToken);
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20TokenRevoke::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20TokenRevokeResult::Ok(res) => break res,
//!         Oauth20TokenRevokeResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20TokenRevokeResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20TokenRevokeResult::Err(err) => panic!("{err}"),
//!     }
//! };
//! # let _ = response;
//! ```

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use io_http::{
    coroutine::*,
    rfc9110::{
        request::HttpRequest,
        send::{HttpSendOutput, HttpSendYield},
    },
    rfc9112::send::{Http11Send, Http11SendError},
};
use log::{debug, trace};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;
use url::{Url, form_urlencoded::Serializer};

/// The revocation response: done, or the params of a rejected request.
pub type Oauth20TokenRevokeResponse = Result<(), Oauth20TokenRevokeErrorParams>;

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20TokenRevokeError {
    /// The HTTP request could not be sent.
    #[error(transparent)]
    SendHttpRevoke(#[from] Http11SendError),
    /// The server answered an error status without an OAuth error body.
    ///
    /// A 503 asks the client to retry later.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1>
    #[error("Unexpected token revocation status {0}")]
    Status(u16),
    /// The server answered with an unexpected redirection.
    #[error("Unexpected redirection {code} to {url}")]
    Redirect {
        /// The redirection target URL.
        url: Url,
        /// The redirection HTTP status code.
        code: u16,
    },
}

/// Result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum Oauth20TokenRevokeResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20TokenRevokeResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20TokenRevokeError),
}

/// The I/O-free coroutine to revoke a token.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7009#section-2>
pub struct Oauth20TokenRevoke {
    send: Http11Send,
}

impl Oauth20TokenRevoke {
    /// Creates a new I/O-free coroutine to revoke a token.
    pub fn new(request: HttpRequest, body: Oauth20TokenRevokeParams) -> Self {
        debug!("prepare token revocation request");
        trace!("url: {}", request.url);

        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_body());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20TokenRevokeResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                debug!("received token revocation response");
                trace!("status: {}", *response.status);
                Oauth20TokenRevokeResult::Ok(Ok(()))
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                debug!("received token revocation error response");
                trace!("status: {}", *response.status);

                match Oauth20TokenRevokeErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20TokenRevokeResult::Ok(Err(res)),
                    Err(_) => {
                        let err = Oauth20TokenRevokeError::Status(*response.status);
                        Oauth20TokenRevokeResult::Err(err)
                    }
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20TokenRevokeResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20TokenRevokeResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20TokenRevokeResult::Err(Oauth20TokenRevokeError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => Oauth20TokenRevokeResult::Err(err.into()),
        }
    }
}

/// The token revocation request parameters.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7009#section-2.1>
#[derive(Debug)]
pub struct Oauth20TokenRevokeParams {
    /// The client identifier.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.2>
    pub client_id: String,
    /// The client secret, for confidential clients.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1>
    pub client_secret: Option<SecretString>,
    /// The token to revoke.
    pub token: SecretString,
    /// The kind of `token`, sparing the server a lookup.
    pub token_type_hint: Option<Oauth20TokenTypeHint>,
}

impl Oauth20TokenRevokeParams {
    /// Builds params from a client id and token, no secret nor hint.
    pub fn new(client_id: impl ToString, token: impl Into<SecretString>) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: None,
            token: token.into(),
            token_type_hint: None,
        }
    }

    /// Serializes the params into the form-urlencoded request body.
    pub fn to_serializer(&self) -> Serializer<'static, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("token", self.token.expose_secret());

        if let Some(hint) = self.token_type_hint {
            serializer.append_pair("token_type_hint", hint.as_str());
        }

        serializer.append_pair("client_id", &self.client_id);

        if let Some(secret) = &self.client_secret {
            serializer.append_pair("client_secret", secret.expose_secret());
        }

        serializer
    }

    /// Builds the form-urlencoded request body.
    // SAFETY: exposes the token and the client secret
    pub fn to_body(&self) -> Vec<u8> {
        self.to_serializer().finish().into_bytes()
    }
}

/// The kind of token a revocation request carries.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7009#section-2.1>
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Oauth20TokenTypeHint {
    /// An access token.
    AccessToken,
    /// A refresh token, revoking the grant's access tokens too when the
    /// server supports it.
    RefreshToken,
}

impl Oauth20TokenTypeHint {
    /// Returns the hint's wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// The error revocation response.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20TokenRevokeErrorParams {
    /// A single ASCII error code.
    pub error: Oauth20TokenRevokeErrorCode,
    /// Human-readable text explaining the error.
    pub error_description: Option<String>,
    /// A URI to a human-readable page about the error.
    pub error_uri: Option<String>,
}

/// Parses error params from JSON bytes.
impl TryFrom<&[u8]> for Oauth20TokenRevokeErrorParams {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The error code of the [`Oauth20TokenRevokeErrorParams`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oauth20TokenRevokeErrorCode {
    /// Client authentication failed.
    InvalidClient,
    /// The request is malformed or missing a required parameter.
    InvalidRequest,
    /// The client may not revoke tokens issued to another client.
    UnauthorizedClient,
    /// The server does not support revoking this kind of token.
    UnsupportedTokenType,
    /// Any unregistered code, kept for provider-specific extensions.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use io_http::rfc9110::request::HttpRequest;
    use url::Url;

    use crate::rfc7009::revoke::*;

    fn revoke(response: &[u8]) -> Oauth20TokenRevokeResult {
        let url = Url::parse("https://example.test/revoke").unwrap();
        let request = HttpRequest {
            method: "POST".into(),
            url,
            headers: Vec::new(),
            body: Vec::new(),
        };

        let params = Oauth20TokenRevokeParams::new("client", "token");
        let mut coroutine = Oauth20TokenRevoke::new(request, params);
        let mut arg = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20TokenRevokeResult::WantsWrite(_) => {}
                Oauth20TokenRevokeResult::WantsRead => arg = Some(response),
                result => return result,
            }
        }
    }

    #[test]
    fn params_send_the_hint_and_client_id() {
        let mut params = Oauth20TokenRevokeParams::new("client", "tok en");
        params.token_type_hint = Some(Oauth20TokenTypeHint::RefreshToken);

        assert_eq!(
            String::from_utf8(params.to_body()).unwrap(),
            "token=tok+en&token_type_hint=refresh_token&client_id=client"
        );
    }

    #[test]
    fn ok_status_revokes() {
        let result = revoke(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert!(matches!(result, Oauth20TokenRevokeResult::Ok(Ok(()))));
    }

    #[test]
    fn error_body_returns_its_code() {
        let body = br#"{"error":"unsupported_token_type"}"#;
        let mut response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 34\r\n\r\n".to_vec();
        response.extend_from_slice(body);

        let Oauth20TokenRevokeResult::Ok(Err(err)) = revoke(&response) else {
            panic!("expected an error response");
        };

        assert_eq!(err.error, Oauth20TokenRevokeErrorCode::UnsupportedTokenType);
    }

    #[test]
    fn unavailable_without_body_returns_its_status() {
        let result = revoke(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");

        assert!(matches!(
            result,
            Oauth20TokenRevokeResult::Err(Oauth20TokenRevokeError::Status(503))
        ));
    }
}
