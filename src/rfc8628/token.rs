//! Device access token request and response (RFC 8628 sections 3.4
//! and 3.5).
//!
//! Polls the token endpoint once with a device code obtained from the
//! auth sibling module.
//!
//! # Example
//!
//! One coroutine performs one poll; the caller waits the interval and retries
//! with a fresh coroutine while the response carries `authorization_pending`.
//!
//! ```rust,no_run
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! use io_http::rfc9110::request::HttpRequest;
//! use io_oauth::rfc8628::token::*;
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
//! let params = Oauth20DeviceAccessTokenRequestParams {
//!     client_id: "client-id".into(),
//!     device_code: "the-device-code".into(),
//! };
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20DeviceAccessTokenRequest::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20DeviceAccessTokenRequestResult::Ok(res) => break res,
//!         Oauth20DeviceAccessTokenRequestResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20DeviceAccessTokenRequestResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20DeviceAccessTokenRequestResult::Err(err) => panic!("{err}"),
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
pub enum Oauth20DeviceAccessTokenRequestError {
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
pub enum Oauth20DeviceAccessTokenRequestResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the
    /// socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20DeviceAccessTokenRequestError),
}

/// The I/O-free coroutine for one device-code poll of the token endpoint.
///
/// A pending authorization surfaces as a successful exchange whose error code
/// is `authorization_pending` (or `slow_down`); the caller waits the interval,
/// then retries with a fresh coroutine (usually over a fresh connection).
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.4>
pub struct Oauth20DeviceAccessTokenRequest {
    send: Http11Send,
}

impl Oauth20DeviceAccessTokenRequest {
    /// Creates the coroutine for one device-code poll.
    pub fn new(request: HttpRequest, body: Oauth20DeviceAccessTokenRequestParams<'_>) -> Self {
        debug!("prepare device access token request");
        trace!("url: {}", request.url);

        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20DeviceAccessTokenRequestResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                debug!("received device access token response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20DeviceAccessTokenRequestResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20DeviceAccessTokenRequestResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                debug!("received device access token error response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20DeviceAccessTokenRequestResult::Ok(Err(res)),
                    Err(err) => Oauth20DeviceAccessTokenRequestResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20DeviceAccessTokenRequestResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20DeviceAccessTokenRequestResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20DeviceAccessTokenRequestResult::Err(
                    Oauth20DeviceAccessTokenRequestError::Redirect {
                        url,
                        code: *response.status,
                    },
                )
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20DeviceAccessTokenRequestResult::Err(err.into())
            }
        }
    }
}

/// The device access token request parameters.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.4>
#[derive(Debug)]
pub struct Oauth20DeviceAccessTokenRequestParams<'a> {
    /// The client identifier.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.2>
    pub client_id: Cow<'a, str>,
    /// The device code obtained from the device authorization response.
    pub device_code: SecretString,
}

impl<'a> Oauth20DeviceAccessTokenRequestParams<'a> {
    /// Serializes the params into the form-urlencoded request body.
    // SAFETY: exposes the device code
    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        serializer.append_pair("client_id", &self.client_id);
        serializer.append_pair("device_code", self.device_code.expose_secret());

        serializer
    }
}

impl fmt::Display for Oauth20DeviceAccessTokenRequestParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_serializer().finish())
    }
}
