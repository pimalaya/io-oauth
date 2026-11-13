//! Access token refresh (RFC 6749 section 6).
//!
//! Trades a refresh token for a fresh access token against the token
//! endpoint, whatever grant issued the refresh token.
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
//! use io_oauth::rfc6749::refresh_access_token::*;
//! use url::Url;
//!
//! let token_url = Url::parse("https://example.com/token").unwrap();
//! let request = HttpRequest {
//!     method: "POST".into(),
//!     url: token_url.clone(),
//!     headers: Vec::new(),
//!     body: Vec::new(),
//! }
//! .header("Host", token_url.host_str().unwrap());
//!
//! let params = Oauth20AccessTokenRefreshParams::new("client-id", "the-refresh-token");
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20AccessTokenRefresh::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20AccessTokenRefreshResult::Ok(res) => break res,
//!         Oauth20AccessTokenRefreshResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20AccessTokenRefreshResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20AccessTokenRefreshResult::Err(err) => panic!("{err}"),
//!     }
//! };
//! # let _ = response;
//! ```

use alloc::{
    borrow::Cow,
    collections::BTreeSet,
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
use thiserror::Error;
use url::{Url, form_urlencoded::Serializer};

use crate::rfc6749::issue_access_token::{
    Oauth20AccessTokenErrorParams, Oauth20AccessTokenResponse, Oauth20AccessTokenSuccessParams,
    parse_http_date,
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20AccessTokenRefreshError {
    /// The HTTP request could not be sent.
    #[error(transparent)]
    SendHttpRefresh(#[from] Http11SendError),
    /// The HTTP response could not be parsed.
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    /// The server answered an error status without an OAuth error body.
    #[error("Unexpected access token refresh status {0}")]
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
pub enum Oauth20AccessTokenRefreshResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20AccessTokenRefreshError),
}

/// The I/O-free coroutine to refresh an access token.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-6>
pub struct Oauth20AccessTokenRefresh {
    send: Http11Send,
}

impl Oauth20AccessTokenRefresh {
    /// Creates a new I/O-free coroutine to refresh an access token.
    pub fn new(request: HttpRequest, body: Oauth20AccessTokenRefreshParams<'_>) -> Self {
        debug!("prepare access token refresh request");
        trace!("url: {}", request.url);

        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_body());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20AccessTokenRefreshResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                debug!("received access token refresh response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20AccessTokenRefreshResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20AccessTokenRefreshResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                debug!("received access token refresh error response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20AccessTokenRefreshResult::Ok(Err(res)),
                    Err(_) => {
                        let err = Oauth20AccessTokenRefreshError::Status(*response.status);
                        Oauth20AccessTokenRefreshResult::Err(err)
                    }
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20AccessTokenRefreshResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20AccessTokenRefreshResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20AccessTokenRefreshResult::Err(Oauth20AccessTokenRefreshError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20AccessTokenRefreshResult::Err(err.into())
            }
        }
    }
}

/// The refresh access token request parameters.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-6>
#[derive(Debug)]
pub struct Oauth20AccessTokenRefreshParams<'a> {
    /// The client identifier.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.2>
    pub client_id: String,
    /// The client secret, for confidential clients.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1>
    pub client_secret: Option<SecretString>,
    /// The refresh token issued with the original grant.
    pub refresh_token: SecretString,
    /// The requested scope, narrowing the original one at most.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub scopes: BTreeSet<Cow<'a, str>>,
}

impl<'a> Oauth20AccessTokenRefreshParams<'a> {
    /// Builds params from a client id and refresh token, no secret nor scope.
    pub fn new(client_id: impl ToString, refresh_token: impl Into<SecretString>) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: None,
            refresh_token: refresh_token.into(),
            scopes: BTreeSet::new(),
        }
    }

    /// Serializes the params into the form-urlencoded request body.
    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "refresh_token");
        serializer.append_pair("client_id", &self.client_id);

        if let Some(secret) = &self.client_secret {
            serializer.append_pair("client_secret", secret.expose_secret());
        }

        serializer.append_pair("refresh_token", self.refresh_token.expose_secret());

        if !self.scopes.is_empty() {
            let mut scope = String::new();
            let mut glue = "";

            for token in &self.scopes {
                scope.push_str(glue);
                scope.push_str(token);
                glue = " ";
            }

            serializer.append_pair("scope", &scope);
        }

        serializer
    }

    /// Builds the form-urlencoded request body.
    // SAFETY: exposes the client secret and the refresh token
    pub fn to_body(&self) -> Vec<u8> {
        self.to_serializer().finish().into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use io_http::rfc9110::request::HttpRequest;
    use url::Url;

    use crate::rfc6749::refresh_access_token::*;

    #[test]
    fn an_error_status_without_oauth_body_returns_its_status() {
        let request = HttpRequest {
            method: "POST".into(),
            url: Url::parse("https://example.test/token").unwrap(),
            headers: Vec::new(),
            body: Vec::new(),
        };

        let params = Oauth20AccessTokenRefreshParams::new("client", "token");
        let mut coroutine = Oauth20AccessTokenRefresh::new(request, params);
        let response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        let mut arg = None;

        let result = loop {
            match coroutine.resume(arg.take()) {
                Oauth20AccessTokenRefreshResult::WantsWrite(_) => {}
                Oauth20AccessTokenRefreshResult::WantsRead => arg = Some(response.as_slice()),
                result => break result,
            }
        };

        assert!(matches!(
            result,
            Oauth20AccessTokenRefreshResult::Err(Oauth20AccessTokenRefreshError::Status(503))
        ));
    }
}
