//! Module dedicated to the sections 3.1 and 3.2: Device Authorization
//! Request and Response.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.1>
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
//! use io_oauth::rfc8628::auth::{
//!     Oauth20RequestDeviceAuth, Oauth20RequestDeviceAuthParams, Oauth20RequestDeviceAuthResult,
//! };
//! use url::Url;
//!
//! let device_url = Url::parse("https://example.com/devicecode").unwrap();
//! let request = HttpRequest {
//!     method: "POST".into(),
//!     url: device_url.clone(),
//!     headers: Vec::new(),
//!     body: Vec::new(),
//! }
//! .header("Host", device_url.host_str().unwrap());
//!
//! let params = Oauth20RequestDeviceAuthParams {
//!     client_id: "client-id".into(),
//!     scope: Default::default(),
//! };
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20RequestDeviceAuth::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20RequestDeviceAuthResult::Ok(res) => break res,
//!         Oauth20RequestDeviceAuthResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20RequestDeviceAuthResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20RequestDeviceAuthResult::Err(err) => panic!("{err}"),
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
use secrecy::SecretString;
use serde::Deserialize;
use thiserror::Error;
use url::{Url, form_urlencoded::Serializer};

use crate::rfc6749::issue_access_token::Oauth20IssueAccessTokenErrorParams;

/// The device authorization response: success params, or error params.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.2>
pub type Oauth20DeviceAuthResponse =
    Result<Oauth20DeviceAuthSuccessParams, Oauth20IssueAccessTokenErrorParams>;

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20RequestDeviceAuthError {
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
pub enum Oauth20RequestDeviceAuthResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20DeviceAuthResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20RequestDeviceAuthError),
}

/// The I/O-free coroutine to request a device and user code pair.
///
/// On success the client shows the user code and verification URI, then polls
/// the token endpoint with the device code.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.1>
pub struct Oauth20RequestDeviceAuth {
    send: Http11Send,
}

impl Oauth20RequestDeviceAuth {
    /// Creates the coroutine to request a device and user code pair.
    pub fn new(request: HttpRequest, body: Oauth20RequestDeviceAuthParams<'_>) -> Self {
        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20RequestDeviceAuthResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20DeviceAuthSuccessParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestDeviceAuthResult::Ok(Ok(res)),
                    Err(err) => Oauth20RequestDeviceAuthResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                match Oauth20IssueAccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestDeviceAuthResult::Ok(Err(res)),
                    Err(err) => Oauth20RequestDeviceAuthResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20RequestDeviceAuthResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20RequestDeviceAuthResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20RequestDeviceAuthResult::Err(Oauth20RequestDeviceAuthError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20RequestDeviceAuthResult::Err(err.into())
            }
        }
    }
}

/// The successful device authorization response.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.2>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20DeviceAuthSuccessParams {
    /// The device code the client polls the token endpoint with.
    pub device_code: SecretString,
    /// The user code the end user types at the verification URI.
    pub user_code: String,
    /// The verification URI shown to the end user.
    pub verification_uri: String,
    /// The verification URI with the user code embedded (e.g. for a QR code).
    ///
    /// Some servers (Microsoft Entra) do not send it.
    pub verification_uri_complete: Option<String>,
    /// The lifetime of the device and user codes, in seconds.
    pub expires_in: usize,
    /// The minimum seconds to wait between polls, defaulting to 5.
    #[serde(default = "default_interval")]
    pub interval: usize,
}

/// Deserializes success params from JSON bytes.
impl TryFrom<&[u8]> for Oauth20DeviceAuthSuccessParams {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The device authorization request parameters.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.1>
#[derive(Debug)]
pub struct Oauth20RequestDeviceAuthParams<'a> {
    /// The client identifier.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.2>
    pub client_id: Cow<'a, str>,
    /// The requested access scope, as space-delimited tokens.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub scope: BTreeSet<Cow<'a, str>>,
}

impl<'a> Oauth20RequestDeviceAuthParams<'a> {
    /// Serializes the params into the form-urlencoded request body.
    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("client_id", &self.client_id);

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

impl fmt::Display for Oauth20RequestDeviceAuthParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_serializer().finish())
    }
}

fn default_interval() -> usize {
    5
}
