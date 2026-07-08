//! Module dedicated to the sections 3.4 and 3.5: Device Access Token
//! Request and Response.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.4>

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

use crate::v2_0::issue_access_token::{
    Oauth20AccessTokenResponse, Oauth20IssueAccessTokenErrorParams,
    Oauth20IssueAccessTokenSuccessParams, parse_http_date,
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20RequestDeviceAccessTokenError {
    #[error(transparent)]
    SendHttpRequest(#[from] Http11SendError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    #[error("Unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
}

/// Result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum Oauth20RequestDeviceAccessTokenResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the
    /// socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20RequestDeviceAccessTokenError),
}

/// The I/O-free coroutine to poll the token endpoint with a device
/// code.
///
/// One coroutine performs one poll attempt: a pending authorization
/// surfaces as a successful HTTP exchange whose error params carry
/// the "authorization_pending" (or "slow_down") code. The caller
/// waits the polling interval, then retries with a fresh coroutine;
/// servers rarely keep the connection alive between attempts, so the
/// caller usually reconnects too.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.4>
pub struct Oauth20RequestDeviceAccessToken {
    send: Http11Send,
}

impl Oauth20RequestDeviceAccessToken {
    /// Creates a new I/O-free coroutine to poll the token endpoint
    /// with a device code.
    pub fn new(request: HttpRequest, body: Oauth20DeviceAccessTokenRequestParams<'_>) -> Self {
        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20RequestDeviceAccessTokenResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20IssueAccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20RequestDeviceAccessTokenResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20RequestDeviceAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                match Oauth20IssueAccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestDeviceAccessTokenResult::Ok(Err(res)),
                    Err(err) => Oauth20RequestDeviceAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20RequestDeviceAccessTokenResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20RequestDeviceAccessTokenResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20RequestDeviceAccessTokenResult::Err(
                    Oauth20RequestDeviceAccessTokenError::Redirect {
                        url,
                        code: *response.status,
                    },
                )
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20RequestDeviceAccessTokenResult::Err(err.into())
            }
        }
    }
}

/// The device access token request parameters.
///
/// While the end user authorizes (or denies) the request at the
/// verification URI, the client polls the token endpoint by adding
/// the following parameters using the
/// "application/x-www-form-urlencoded" format in the HTTP request
/// entity-body.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.4>
#[derive(Debug)]
pub struct Oauth20DeviceAccessTokenRequestParams<'a> {
    pub client_id: Cow<'a, str>,
    pub device_code: SecretString,
}

impl<'a> Oauth20DeviceAccessTokenRequestParams<'a> {
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
