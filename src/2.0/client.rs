//! Std-blocking OAuth 2.0 client wrapping a single boxed stream.
//!
//! Two construction paths:
//! - [`Oauth20ClientStd::new`] wraps any pre-connected
//!   `Read + Write + Send` stream. Callers own connection setup
//!   (TCP, TLS, etc.).
//! - [`Oauth20ClientStd::connect`] (TLS-gated) opens the TCP/TLS stream
//!   itself via [`pimalaya_stream::std::stream::StreamStd`].
//!
//! Per-operation methods inline the coroutine loop against the
//! client's stream.

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

use crate::v2_0::{
    authorization_code_grant::access_token_request::{
        Oauth20AccessTokenRequestParams, Oauth20RequestAccessToken, Oauth20RequestAccessTokenError,
        Oauth20RequestAccessTokenResult,
    },
    device_authorization_grant::{
        device_access_token_request::{
            Oauth20DeviceAccessTokenRequestParams, Oauth20RequestDeviceAccessToken,
            Oauth20RequestDeviceAccessTokenError, Oauth20RequestDeviceAccessTokenResult,
        },
        device_authorization_request::{
            Oauth20DeviceAuthorizationRequestParams, Oauth20DeviceAuthorizationResponse,
            Oauth20RequestDeviceAuthorization, Oauth20RequestDeviceAuthorizationError,
            Oauth20RequestDeviceAuthorizationResult,
        },
    },
    issue_access_token::Oauth20AccessTokenResponse,
    refresh_access_token::{
        Oauth20RefreshAccessToken, Oauth20RefreshAccessTokenError, Oauth20RefreshAccessTokenParams,
        Oauth20RefreshAccessTokenResult,
    },
};
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use crate::v2_0::{
    device_authorization_grant::device_authorization_request::Oauth20DeviceAuthorizationSuccessParams,
    issue_access_token::Oauth20IssueAccessTokenErrorCode,
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`Oauth20ClientStd`].
#[derive(Debug, Error)]
pub enum Oauth20ClientStdError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    RequestAccessToken(#[from] Oauth20RequestAccessTokenError),
    #[error(transparent)]
    RefreshAccessToken(#[from] Oauth20RefreshAccessTokenError),
    #[error(transparent)]
    RequestDeviceAuthorization(#[from] Oauth20RequestDeviceAuthorizationError),
    #[error(transparent)]
    RequestDeviceAccessToken(#[from] Oauth20RequestDeviceAccessTokenError),

    #[error("OAuth 2.0 device code expired before the user completed authorization")]
    DeviceCodeExpired,

    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    #[error(transparent)]
    Tls(#[from] anyhow::Error),

    #[error("OAuth 2.0 URL `{0}` has no host")]
    UrlMissingHost(String),
    #[error("OAuth 2.0 URL `{0}` has no port")]
    UrlMissingPort(String),
    #[error("OAuth 2.0 URL `{0}` has unsupported scheme `{1}` (expected `http` or `https`)")]
    UrlUnsupportedScheme(String, String),

    #[error("Malformed HTTP request received on redirect server: `{0}`")]
    InvalidRedirectRequest(String),
}

/// Marker trait for streams the client wraps; implemented for any
/// blocking `Read + Write + Send` stream.
pub trait Oauth20Stream: Read + Write + Send {}
impl<T: Read + Write + Send + ?Sized> Oauth20Stream for T {}

/// Std-blocking OAuth 2.0 client wrapping a single boxed stream.
pub struct Oauth20ClientStd {
    pub stream: Box<dyn Oauth20Stream>,
    pub token_endpoint: Url,
    pub client_id: String,
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

    /// Opens a TLS-aware connection to `token_endpoint` and returns
    /// a client ready to issue requests against it.
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
        let stream = Self::open_stream(&token_endpoint, tls)?;
        Ok(Self::new(stream, token_endpoint, client_id))
    }

    /// Opens a TCP or TLS stream to the given endpoint, depending on
    /// its scheme.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    fn open_stream(endpoint: &Url, tls: &Tls) -> Result<StreamStd, Oauth20ClientStdError> {
        let host = endpoint
            .host_str()
            .ok_or_else(|| Oauth20ClientStdError::UrlMissingHost(endpoint.to_string()))?;
        let port = endpoint
            .port_or_known_default()
            .ok_or_else(|| Oauth20ClientStdError::UrlMissingPort(endpoint.to_string()))?;

        match endpoint.scheme() {
            scheme if scheme.eq_ignore_ascii_case("https") => {
                Ok(StreamStd::connect_tls(host, port, tls)?)
            }
            scheme if scheme.eq_ignore_ascii_case("http") => {
                Ok(StreamStd::connect_tcp(host, port)?)
            }
            scheme => Err(Oauth20ClientStdError::UrlUnsupportedScheme(
                endpoint.to_string(),
                scheme.to_string(),
            )),
        }
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
        let mut coroutine = Oauth20RequestAccessToken::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20RequestAccessTokenResult::Ok(res) => return Ok(res),
                Oauth20RequestAccessTokenResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20RequestAccessTokenResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20RequestAccessTokenResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Refreshes an access token using a refresh token.
    pub fn refresh_access_token(
        &mut self,
        params: Oauth20RefreshAccessTokenParams<'_>,
    ) -> Result<Oauth20AccessTokenResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(&self.token_endpoint);
        let mut coroutine = Oauth20RefreshAccessToken::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20RefreshAccessTokenResult::Ok(res) => return Ok(res),
                Oauth20RefreshAccessTokenResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20RefreshAccessTokenResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20RefreshAccessTokenResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Requests a device and user code pair from the device
    /// authorization endpoint, which usually shares its host with the
    /// token endpoint the client's stream is connected to.
    pub fn request_device_authorization(
        &mut self,
        endpoint: &Url,
        params: Oauth20DeviceAuthorizationRequestParams<'_>,
    ) -> Result<Oauth20DeviceAuthorizationResponse, Oauth20ClientStdError> {
        let request = self.build_post_request(endpoint);
        let mut coroutine = Oauth20RequestDeviceAuthorization::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20RequestDeviceAuthorizationResult::Ok(res) => return Ok(res),
                Oauth20RequestDeviceAuthorizationResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20RequestDeviceAuthorizationResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20RequestDeviceAuthorizationResult::Err(err) => return Err(err.into()),
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
        let mut coroutine = Oauth20RequestDeviceAccessToken::new(request, params);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20RequestDeviceAccessTokenResult::Ok(res) => return Ok(res),
                Oauth20RequestDeviceAccessTokenResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                Oauth20RequestDeviceAccessTokenResult::WantsWrite(bytes) => {
                    self.stream.write_all(&bytes)?;
                }
                Oauth20RequestDeviceAccessTokenResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Polls the token endpoint until the end user completes (or
    /// denies) the device authorization, then returns the token
    /// response.
    ///
    /// The caller displays the user code and verification URI from
    /// `device` before calling this method, which then blocks: it
    /// sleeps the polling interval between attempts (increased by 5
    /// seconds on "slow_down" as required by RFC 8628 §3.5),
    /// reconnects the stream for every attempt since authorization
    /// servers rarely keep it alive across intervals, and gives up
    /// with [`Oauth20ClientStdError::DeviceCodeExpired`] once the
    /// device code lifetime is exceeded.
    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    pub fn await_device_access_token(
        &mut self,
        tls: &Tls,
        device: &Oauth20DeviceAuthorizationSuccessParams,
    ) -> Result<Oauth20AccessTokenResponse, Oauth20ClientStdError> {
        let deadline = Instant::now() + Duration::from_secs(device.expires_in as u64);
        let mut interval = Duration::from_secs(device.interval as u64);

        loop {
            thread::sleep(interval);

            if Instant::now() >= deadline {
                return Err(Oauth20ClientStdError::DeviceCodeExpired);
            }

            let stream = Self::open_stream(&self.token_endpoint, tls)?;
            self.stream = Box::new(stream);

            let params = Oauth20DeviceAccessTokenRequestParams {
                client_id: self.client_id.clone().into(),
                device_code: device.device_code.clone(),
            };

            match self.request_device_access_token(params)? {
                Ok(success) => return Ok(Ok(success)),
                Err(err) => match err.error {
                    Oauth20IssueAccessTokenErrorCode::AuthorizationPending => continue,
                    Oauth20IssueAccessTokenErrorCode::SlowDown => {
                        interval += Duration::from_secs(5);
                    }
                    _ => return Ok(Err(err)),
                },
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

/// Binds a local TCP listener on `redirect_uri`, waits for the
/// authorization server's redirect, sends a `200 OK` placeholder
/// response, and returns the redirected URL (carrying `code` and
/// `state`).
///
/// Single-shot: the listener closes once one redirect is handled.
/// PKCE verifier and original state are tracked by the caller (this
/// fn only forwards the URL).
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
