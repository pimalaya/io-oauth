//! Std-blocking OAuth 2.0 client wrapping a single boxed stream.
//!
//! [`Oauth20ClientStd::new`] wraps any pre-connected `Read + Write + Send`
//! stream, while the TLS-gated [`Oauth20ClientStd::connect`] opens the TCP/TLS
//! stream itself. Per-operation methods inline the coroutine loop against the
//! client's stream. The client spans the RFC modules (token operations, device
//! grant, dynamic client registration), hence its home at the crate root; a
//! future OAuth version would add its own client alongside, unified behind a
//! version-agnostic `OauthClientStd` wrapper only once one exists.

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener},
};
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use std::{
    thread,
    time::{Duration, Instant},
};

use io_http::{rfc7617::basic::HttpAuthBasic, rfc9110::request::HttpRequest};
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::Url;

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use crate::{
    rfc6749::issue_access_token::Oauth20AccessTokenErrorCode,
    rfc8628::auth::Oauth20DeviceAuthSuccessParams,
};
use crate::{
    rfc6749::{
        access_token_request::*, client_credentials::*, issue_access_token::*,
        refresh_access_token::*,
    },
    rfc7591::register::*,
    rfc8628::{auth::*, token::*},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`Oauth20ClientStd`].
#[derive(Debug, Error)]
pub enum Oauth20ClientStdError {
    /// The underlying stream I/O failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The authorization code exchange failed.
    #[error(transparent)]
    AccessTokenRequest(#[from] Oauth20AccessTokenRequestError),
    /// The token refresh failed.
    #[error(transparent)]
    AccessTokenRefresh(#[from] Oauth20AccessTokenRefreshError),
    /// The client credentials exchange failed.
    #[error(transparent)]
    ClientCredentialsRequest(#[from] Oauth20ClientCredentialsRequestError),
    /// The device authorization request failed.
    #[error(transparent)]
    DeviceAuthRequest(#[from] Oauth20DeviceAuthRequestError),
    /// A device access token poll failed.
    #[error(transparent)]
    DeviceAccessTokenRequest(#[from] Oauth20DeviceAccessTokenRequestError),
    /// The device code expired before the user completed the flow.
    #[error("OAuth 2.0 device code expired before the user completed authorization")]
    DeviceCodeExpired,
    /// The client registration failed.
    #[error(transparent)]
    ClientRegister(#[from] Oauth20ClientRegisterError),
    /// The client registration params could not be serialized.
    #[error("Serialize OAuth 2.0 client registration params: {0}")]
    SerializeClientRegisterParams(serde_json::Error),
    /// Opening the TCP/TLS connection failed.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error(transparent)]
    Tls(#[from] anyhow::Error),
    /// The endpoint URL has no host.
    #[error("OAuth 2.0 URL `{0}` has no host")]
    UrlMissingHost(String),
    /// The endpoint URL has no port and no known default.
    #[error("OAuth 2.0 URL `{0}` has no port")]
    UrlMissingPort(String),
    /// The endpoint URL scheme is neither `http` nor `https`.
    #[error("OAuth 2.0 URL `{url}` has unsupported scheme `{scheme}` (expected `http` or `https`)")]
    UrlUnsupportedScheme {
        /// The offending endpoint URL.
        url: String,
        /// The unsupported scheme it carries.
        scheme: String,
    },
    /// The redirect server received a malformed HTTP request.
    #[error("Malformed HTTP request received on redirect server: `{0}`")]
    InvalidRedirectRequest(String),
}

/// Std-blocking OAuth 2.0 client wrapping a single boxed stream.
pub struct Oauth20ClientStd {
    /// The connected stream to the token endpoint.
    pub stream: Box<dyn Oauth20Stream>,
    /// The token endpoint the client issues requests against.
    pub token_endpoint: Url,
    /// The client identifier.
    pub client_id: String,
    /// The client secret, for confidential clients.
    pub client_secret: Option<SecretString>,
}

impl Oauth20ClientStd {
    /// Builds a client around `stream`. The caller is responsible for
    /// opening the connection (TCP, TLS handshake if needed).
    pub fn new<S: Read + Write + Send + 'static>(
        stream: S,
        token_endpoint: Url,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            stream: Box::new(stream),
            token_endpoint,
            client_id: client_id.into(),
            client_secret: None,
        }
    }

    /// Opens a TLS-aware connection to `token_endpoint` and returns a
    /// client ready to issue requests against it. `http://` is plain
    /// TCP, `https://` is implicit TLS.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    pub fn connect(
        token_endpoint: Url,
        tls: &Tls,
        client_id: impl Into<String>,
    ) -> Result<Self, Oauth20ClientStdError> {
        let host = token_endpoint
            .host_str()
            .ok_or_else(|| Oauth20ClientStdError::UrlMissingHost(token_endpoint.to_string()))?;
        let port = token_endpoint
            .port_or_known_default()
            .ok_or_else(|| Oauth20ClientStdError::UrlMissingPort(token_endpoint.to_string()))?;

        let stream = match token_endpoint.scheme() {
            scheme if scheme.eq_ignore_ascii_case("https") => {
                StreamStd::connect_tls(host, port, tls)?
            }
            scheme if scheme.eq_ignore_ascii_case("http") => StreamStd::connect_tcp(host, port)?,
            scheme => {
                return Err(Oauth20ClientStdError::UrlUnsupportedScheme {
                    url: token_endpoint.to_string(),
                    scheme: scheme.to_string(),
                });
            }
        };

        Ok(Self::new(stream, token_endpoint, client_id))
    }

    /// Replaces the underlying stream.
    pub fn set_stream<S: Read + Write + Send + 'static>(&mut self, stream: S) {
        self.stream = Box::new(stream);
    }

    /// Exchanges an authorization code for an access token.
    pub fn request_access_token(
        &mut self,
        params: Oauth20AccessTokenRequestParams<'_>,
    ) -> Result<Oauth20AccessTokenResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(&self.token_endpoint);
        let mut coroutine = Oauth20AccessTokenRequest::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20AccessTokenRequestResult::Ok(res) => return Ok(res),
                Oauth20AccessTokenRequestResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20AccessTokenRequestResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20AccessTokenRequestResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Refreshes an access token using a refresh token.
    pub fn refresh_access_token(
        &mut self,
        params: Oauth20AccessTokenRefreshParams<'_>,
    ) -> Result<Oauth20AccessTokenResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(&self.token_endpoint);
        let mut coroutine = Oauth20AccessTokenRefresh::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20AccessTokenRefreshResult::Ok(res) => return Ok(res),
                Oauth20AccessTokenRefreshResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20AccessTokenRefreshResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20AccessTokenRefreshResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Requests an access token with the client credentials grant.
    ///
    /// The client authenticates with its own credentials (the Basic
    /// `Authorization` header set from `client_secret`) and receives a
    /// token scoped to resources under its own control. No refresh
    /// token is issued; the caller repeats the request on expiry.
    pub fn request_client_credentials(
        &mut self,
        params: Oauth20ClientCredentialsRequestParams<'_>,
    ) -> Result<Oauth20AccessTokenResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(&self.token_endpoint);
        let mut coroutine = Oauth20ClientCredentialsRequest::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20ClientCredentialsRequestResult::Ok(res) => return Ok(res),
                Oauth20ClientCredentialsRequestResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20ClientCredentialsRequestResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20ClientCredentialsRequestResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Requests a device and user code pair from the device authorization
    /// endpoint (usually the token endpoint's host).
    pub fn request_device_auth(
        &mut self,
        endpoint: &Url,
        params: Oauth20DeviceAuthRequestParams<'_>,
    ) -> Result<Oauth20DeviceAuthResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(endpoint);
        let mut coroutine = Oauth20DeviceAuthRequest::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20DeviceAuthRequestResult::Ok(res) => return Ok(res),
                Oauth20DeviceAuthRequestResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20DeviceAuthRequestResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20DeviceAuthRequestResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Polls the token endpoint once with a device code.
    ///
    /// A pending authorization surfaces as an error params response
    /// carrying the "authorization_pending" (or "slow_down") code;
    /// the caller waits the polling interval, then retries, usually
    /// over a fresh stream (see [`Self::await_device_access_token`]).
    pub fn request_device_access_token(
        &mut self,
        params: Oauth20DeviceAccessTokenRequestParams<'_>,
    ) -> Result<Oauth20AccessTokenResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(&self.token_endpoint);
        let mut coroutine = Oauth20DeviceAccessTokenRequest::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20DeviceAccessTokenRequestResult::Ok(res) => return Ok(res),
                Oauth20DeviceAccessTokenRequestResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20DeviceAccessTokenRequestResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20DeviceAccessTokenRequestResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Polls the token endpoint until the end user completes or denies the
    /// device authorization, then returns the token response.
    ///
    /// Blocks: it sleeps the polling interval between attempts (increased by 5s
    /// on `slow_down`), reconnects each attempt since servers rarely keep the
    /// socket alive, and gives up with
    /// [`Oauth20ClientStdError::DeviceCodeExpired`] past the code lifetime.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    pub fn await_device_access_token(
        &mut self,
        tls: &Tls,
        device: &Oauth20DeviceAuthSuccessParams,
    ) -> Result<Oauth20AccessTokenResponse, Oauth20ClientStdError> {
        let deadline = Instant::now() + Duration::from_secs(device.expires_in as u64);
        let mut interval = Duration::from_secs(device.interval as u64);

        loop {
            thread::sleep(interval);

            if Instant::now() >= deadline {
                return Err(Oauth20ClientStdError::DeviceCodeExpired);
            }

            // NOTE: authorization servers rarely keep the socket alive
            // between polls, so reopen a fresh connection each attempt
            // (keeping our own client_secret).
            self.stream =
                Self::connect(self.token_endpoint.clone(), tls, self.client_id.clone())?.stream;

            let params = Oauth20DeviceAccessTokenRequestParams {
                client_id: self.client_id.clone().into(),
                device_code: device.device_code.clone(),
            };

            match self.request_device_access_token(params)? {
                Ok(success) => return Ok(Ok(success)),
                Err(err) => match err.error {
                    Oauth20AccessTokenErrorCode::AuthorizationPending => continue,
                    Oauth20AccessTokenErrorCode::SlowDown => {
                        interval += Duration::from_secs(5);
                    }
                    _ => return Ok(Err(err)),
                },
            }
        }
    }

    /// Registers a client dynamically against `endpoint` (RFC 7591).
    ///
    /// The registration endpoint usually lives on the token
    /// endpoint's host; when it does not, wrap a stream connected to
    /// it instead (see [`Self::set_stream`]). Returns the server's
    /// response: the issued client information, or the params of a
    /// rejected registration.
    pub fn register_client(
        &mut self,
        endpoint: &Url,
        params: &Oauth20ClientRegisterParams,
    ) -> Result<Oauth20ClientRegisterResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(endpoint);
        let mut coroutine = Oauth20ClientRegister::new(request, params)
            .map_err(Oauth20ClientStdError::SerializeClientRegisterParams)?;
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20ClientRegisterResult::Ok(res) => return Ok(res),
                Oauth20ClientRegisterResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20ClientRegisterResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20ClientRegisterResult::Err(err) => return Err(err.into()),
            }
        }
    }

    fn build_post_request(&self, endpoint: &Url) -> HttpRequest {
        let host = endpoint.host_str().unwrap_or("");
        let port = endpoint.port_or_known_default().unwrap_or(0);

        let mut request = HttpRequest {
            method: "POST".into(),
            url: endpoint.clone(),
            headers: Vec::new(),
            body: Vec::new(),
        }
        .header("Host", format!("{host}:{port}"));

        if let Some(secret) = &self.client_secret {
            let creds = HttpAuthBasic::new(self.client_id.clone(), secret.expose_secret());
            request = request.header("Authorization", creds.to_authorization());
        }

        request
    }
}

/// Marker trait for streams the client wraps; implemented for any
/// blocking `Read + Write + Send` stream.
pub trait Oauth20Stream: Read + Write + Send {}
impl<T: Read + Write + Send + ?Sized> Oauth20Stream for T {}

/// Waits on a local TCP listener for the authorization redirect and returns
/// the redirected URL (carrying `code` and `state`).
///
/// Single-shot: the listener closes once one redirect is handled, answering a
/// `200 OK` placeholder. The PKCE verifier and original state are the caller's
/// to track.
pub fn await_redirect(redirect_uri: &Url) -> Result<Url, Oauth20ClientStdError> {
    let scheme = redirect_uri.scheme();
    let host = redirect_uri
        .host_str()
        .ok_or_else(|| Oauth20ClientStdError::UrlMissingHost(redirect_uri.to_string()))?;
    let port = redirect_uri
        .port_or_known_default()
        .ok_or_else(|| Oauth20ClientStdError::UrlMissingPort(redirect_uri.to_string()))?;

    let listener = TcpListener::bind((host, port))?;
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(&mut stream);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let redirected_path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Oauth20ClientStdError::InvalidRedirectRequest(request_line.clone()))?;

    let redirected_uri: Url = format!("{scheme}://{host}:{port}{redirected_path}")
        .parse()
        .map_err(|_| Oauth20ClientStdError::InvalidRedirectRequest(request_line.clone()))?;

    let stream = reader.into_inner();
    stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nAuthorization succeeded!")?;
    stream.shutdown(Shutdown::Both)?;

    Ok(redirected_uri)
}
