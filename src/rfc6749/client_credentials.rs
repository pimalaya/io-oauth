//! Module dedicated to the section 4.4: Client Credentials Grant.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.4>
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
//! use io_oauth::rfc6749::client_credentials::{
//!     Oauth20RequestClientCredentials, Oauth20RequestClientCredentialsParams,
//!     Oauth20RequestClientCredentialsResult,
//! };
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
//! let params = Oauth20RequestClientCredentialsParams::default();
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20RequestClientCredentials::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20RequestClientCredentialsResult::Ok(res) => break res,
//!         Oauth20RequestClientCredentialsResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20RequestClientCredentialsResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20RequestClientCredentialsResult::Err(err) => panic!("{err}"),
//!     }
//! };
//! # let _ = response;
//! ```

use core::fmt;

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
use thiserror::Error;
use url::{Url, form_urlencoded::Serializer};

use crate::rfc6749::issue_access_token::{
    Oauth20AccessTokenResponse, Oauth20IssueAccessTokenErrorParams,
    Oauth20IssueAccessTokenSuccessParams, parse_http_date,
};

/// The client credentials grant request parameters.
///
/// The client is authenticated by the token endpoint (typically an HTTP Basic
/// `Authorization` header), so the body only carries the grant type and scope.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2>
#[derive(Debug, Default)]
pub struct Oauth20RequestClientCredentialsParams<'a> {
    /// The scope of the access request.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub scope: BTreeSet<Cow<'a, str>>,
}

impl<'a> Oauth20RequestClientCredentialsParams<'a> {
    /// Serializes the params into the form-urlencoded request body.
    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "client_credentials");

        if !self.scope.is_empty() {
            let mut scope = String::new();
            let mut glue = "";

            for token in &self.scope {
                scope.push_str(glue);
                scope.push_str(token);
                glue = " ";
            }

            serializer.append_pair("scope", &scope);
        }

        serializer
    }
}

impl fmt::Display for Oauth20RequestClientCredentialsParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_serializer().finish())
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20RequestClientCredentialsError {
    /// The HTTP request could not be sent.
    #[error(transparent)]
    SendHttpRequest(#[from] Http11SendError),
    /// The HTTP response could not be parsed.
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
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
pub enum Oauth20RequestClientCredentialsResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20RequestClientCredentialsError),
}

/// The I/O-free coroutine to request an access token with the client
/// credentials grant.
///
/// The grant issues no refresh token: the client repeats the request when the
/// token expires.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.4>
pub struct Oauth20RequestClientCredentials {
    send: Http11Send,
}

impl Oauth20RequestClientCredentials {
    /// Creates the coroutine to request a client credentials access token.
    pub fn new(request: HttpRequest, body: Oauth20RequestClientCredentialsParams<'_>) -> Self {
        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20RequestClientCredentialsResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20IssueAccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20RequestClientCredentialsResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20RequestClientCredentialsResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                match Oauth20IssueAccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestClientCredentialsResult::Ok(Err(res)),
                    Err(err) => Oauth20RequestClientCredentialsResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20RequestClientCredentialsResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20RequestClientCredentialsResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20RequestClientCredentialsResult::Err(
                    Oauth20RequestClientCredentialsError::Redirect {
                        url,
                        code: *response.status,
                    },
                )
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20RequestClientCredentialsResult::Err(err.into())
            }
        }
    }
}
