//! Module dedicated to the section 4.1.3: Access Token Request.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3>
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
//! use io_oauth::rfc6749::access_token_request::{
//!     Oauth20RequestAccessToken, Oauth20RequestAccessTokenParams,
//!     Oauth20RequestAccessTokenResult,
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
//! let params = Oauth20RequestAccessTokenParams {
//!     code: "the-authorization-code".into(),
//!     redirect_uri: None,
//!     client_id: "client-id".into(),
//!     client_secret: None,
//!     pkce_code_verifier: None,
//! };
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20RequestAccessToken::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20RequestAccessTokenResult::Ok(res) => break res,
//!         Oauth20RequestAccessTokenResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20RequestAccessTokenResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20RequestAccessTokenResult::Err(err) => panic!("{err}"),
//!     }
//! };
//! # let _ = response;
//! ```

use core::fmt;

use alloc::{
    borrow::Cow,
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
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::{Url, form_urlencoded::Serializer};

use crate::{
    rfc6749::issue_access_token::{
        Oauth20AccessTokenResponse, Oauth20IssueAccessTokenErrorParams,
        Oauth20IssueAccessTokenSuccessParams, parse_http_date,
    },
    rfc7636::pkce::Oauth20PkceCodeVerifier,
};

/// The access token request parameters, exchanging the authorization code.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3>
pub struct Oauth20RequestAccessTokenParams<'a> {
    /// The authorization code received on the redirect.
    pub code: Cow<'a, str>,
    /// The redirection URI, when it was part of the authorization request.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2>
    pub redirect_uri: Option<Cow<'a, str>>,
    /// The client identifier.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.2>
    pub client_id: Cow<'a, str>,
    /// The client secret, for confidential clients.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1>
    pub client_secret: Option<SecretString>,
    /// The PKCE code verifier, when the flow uses PKCE (RFC 7636).
    pub pkce_code_verifier: Option<Cow<'a, Oauth20PkceCodeVerifier>>,
}

impl<'a> Oauth20RequestAccessTokenParams<'a> {
    /// Serializes the params into the form-urlencoded request body.
    // SAFETY: this function exposes the code and the PKCE code verifier
    pub fn to_form_url_encoded_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "authorization_code");
        serializer.append_pair("code", &self.code);

        if let Some(uri) = &self.redirect_uri {
            serializer.append_pair("redirect_uri", uri);
        }

        serializer.append_pair("client_id", &self.client_id);

        if let Some(secret) = &self.client_secret {
            serializer.append_pair("client_secret", secret.expose_secret());
        }

        if let Some(verifier) = &self.pkce_code_verifier {
            let verifier = String::from_utf8_lossy(verifier.expose());
            serializer.append_pair("code_verifier", &verifier);
        }

        serializer
    }
}

impl fmt::Display for Oauth20RequestAccessTokenParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_form_url_encoded_serializer().finish())
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20RequestAccessTokenError {
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
pub enum Oauth20RequestAccessTokenResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20RequestAccessTokenError),
}

/// The I/O-free coroutine to exchange an authorization code for an access
/// token.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1>
#[derive(Debug)]
pub struct Oauth20RequestAccessToken {
    send: Http11Send,
}

impl Oauth20RequestAccessToken {
    /// Creates the coroutine to exchange an authorization code.
    pub fn new(request: HttpRequest, body: Oauth20RequestAccessTokenParams<'_>) -> Self {
        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20RequestAccessTokenResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20IssueAccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20RequestAccessTokenResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20RequestAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                match Oauth20IssueAccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestAccessTokenResult::Ok(Err(res)),
                    Err(err) => Oauth20RequestAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20RequestAccessTokenResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20RequestAccessTokenResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20RequestAccessTokenResult::Err(Oauth20RequestAccessTokenError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20RequestAccessTokenResult::Err(err.into())
            }
        }
    }
}
