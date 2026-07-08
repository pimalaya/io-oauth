//! Module dedicated to the sections 3.1 and 3.2: Device Authorization
//! Request and Response.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.1>

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

use crate::v2_0::issue_access_token::Oauth20IssueAccessTokenErrorParams;

pub type Oauth20DeviceAuthorizationResponse =
    Result<Oauth20DeviceAuthorizationSuccessParams, Oauth20IssueAccessTokenErrorParams>;

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20RequestDeviceAuthorizationError {
    #[error(transparent)]
    SendHttpRequest(#[from] Http11SendError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    #[error("Unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
}

/// Result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum Oauth20RequestDeviceAuthorizationResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20DeviceAuthorizationResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the
    /// socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20RequestDeviceAuthorizationError),
}

/// The I/O-free coroutine to request a device and user code pair.
///
/// This coroutine sends the device authorization HTTP request to the
/// device authorization endpoint and receives either a successful or
/// an error HTTP response. On success the client displays the user
/// code and verification URI to the end user, then polls the token
/// endpoint with the device code.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.1>
pub struct Oauth20RequestDeviceAuthorization {
    send: Http11Send,
}

impl Oauth20RequestDeviceAuthorization {
    /// Creates a new I/O-free coroutine to request a device and user
    /// code pair.
    pub fn new(request: HttpRequest, body: Oauth20DeviceAuthorizationRequestParams<'_>) -> Self {
        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20RequestDeviceAuthorizationResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20DeviceAuthorizationSuccessParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestDeviceAuthorizationResult::Ok(Ok(res)),
                    Err(err) => Oauth20RequestDeviceAuthorizationResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                match Oauth20IssueAccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestDeviceAuthorizationResult::Ok(Err(res)),
                    Err(err) => Oauth20RequestDeviceAuthorizationResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20RequestDeviceAuthorizationResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20RequestDeviceAuthorizationResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20RequestDeviceAuthorizationResult::Err(
                    Oauth20RequestDeviceAuthorizationError::Redirect {
                        url,
                        code: *response.status,
                    },
                )
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20RequestDeviceAuthorizationResult::Err(err.into())
            }
        }
    }
}

/// The response returned by the authorization server when the device
/// authorization request is valid.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.2>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20DeviceAuthorizationSuccessParams {
    /// The device verification code, used by the client to poll the
    /// token endpoint. Not intended to be displayed to the end user.
    pub device_code: SecretString,

    /// The end-user verification code, displayed to the end user who
    /// types it at the verification URI.
    pub user_code: String,

    /// The end-user verification URI on the authorization server,
    /// displayed to the end user.
    pub verification_uri: String,

    /// A verification URI that includes the user code, designed for
    /// non-textual transmission (e.g. rendered as a QR code). Some
    /// servers (e.g. Microsoft Entra) do not send it.
    pub verification_uri_complete: Option<String>,

    /// The lifetime in seconds of the device and user codes.
    pub expires_in: usize,

    /// The minimum amount of time in seconds that the client SHOULD
    /// wait between polling requests to the token endpoint. Defaults
    /// to 5 when the server does not send it, as required by the RFC.
    #[serde(default = "default_interval")]
    pub interval: usize,
}

/// Deserializes success params from JSON bytes.
impl TryFrom<&[u8]> for Oauth20DeviceAuthorizationSuccessParams {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The device authorization request parameters.
///
/// The client initiates the flow by sending these parameters using
/// the "application/x-www-form-urlencoded" format to the device
/// authorization endpoint.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.1>
#[derive(Debug)]
pub struct Oauth20DeviceAuthorizationRequestParams<'a> {
    pub client_id: Cow<'a, str>,
    pub scope: BTreeSet<Cow<'a, str>>,
}

impl<'a> Oauth20DeviceAuthorizationRequestParams<'a> {
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

impl fmt::Display for Oauth20DeviceAuthorizationRequestParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_serializer().finish())
    }
}

fn default_interval() -> usize {
    5
}
