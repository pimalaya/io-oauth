//! Client registration request and response (RFC 7591 section 3).
//!
//! Registers a client dynamically against the registration endpoint
//! advertised by the RFC 8414 server metadata, sparing any provider
//! console: a public client registers with the none token endpoint
//! auth method and needs no secret.
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
//! use io_oauth::rfc7591::register::*;
//! use url::Url;
//!
//! let registration_url = Url::parse("https://example.com/register").unwrap();
//! let request = HttpRequest {
//!     method: "POST".into(),
//!     url: registration_url.clone(),
//!     headers: Vec::new(),
//!     body: Vec::new(),
//! }
//! .header("Host", registration_url.host_str().unwrap());
//!
//! let params = Oauth20ClientRegisterParams {
//!     client_name: Some("My App".into()),
//!     redirect_uris: vec!["http://127.0.0.1/redirect".into()],
//!     token_endpoint_auth_method: Some("none".into()),
//!     ..Default::default()
//! };
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20ClientRegister::new(request, &params).unwrap();
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20ClientRegisterResult::Ok(res) => break res,
//!         Oauth20ClientRegisterResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20ClientRegisterResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20ClientRegisterResult::Err(err) => panic!("{err}"),
//!     }
//! };
//! # let _ = response;
//! ```

use alloc::{string::String, vec::Vec};

use io_http::{
    coroutine::*,
    rfc9110::{
        request::HttpRequest,
        send::{HttpSendOutput, HttpSendYield},
    },
    rfc9112::send::{Http11Send, Http11SendError},
};
use log::{debug, trace};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// The registration response: client information, or error params.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7591#section-3.2>
pub type Oauth20ClientRegisterResponse =
    Result<Oauth20ClientInformation, Oauth20ClientRegisterErrorParams>;

/// The client metadata sent to the registration endpoint.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7591#section-2>
#[derive(Clone, Debug, Default, Serialize)]
pub struct Oauth20ClientRegisterParams {
    /// The redirection URIs the client will use in authorization requests.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// The client authentication method for the token endpoint (`none` for a
    /// public client without secret).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// The grant types the client will use (`authorization_code`,
    /// `refresh_token`, ...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<String>,
    /// The response types the client will use (`code`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<String>,
    /// Human-readable name of the client, shown on consent screens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// URL of the client's home page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    /// URL of the client's logo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// Space-separated scope values the client will request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Contact addresses of people responsible for the client.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    /// URL of the client's terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    /// URL of the client's privacy policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    /// Identifier of the client software, stable across dynamic registrations
    /// of the same software.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,
    /// Version of the client software.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
}

/// The information issued for a successfully registered client.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20ClientInformation {
    /// The issued client identifier.
    pub client_id: String,
    /// The issued client secret; absent for public clients.
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// Unix epoch seconds when the client identifier was issued.
    #[serde(default)]
    pub client_id_issued_at: Option<u64>,
    /// Unix epoch seconds when the client secret expires, 0 for never; absent
    /// without a secret.
    #[serde(default)]
    pub client_secret_expires_at: Option<u64>,
}

/// Deserializes client information from JSON bytes.
impl TryFrom<&[u8]> for Oauth20ClientInformation {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The response returned by the registration endpoint when the client metadata
/// is invalid.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20ClientRegisterErrorParams {
    /// A single ASCII error code.
    pub error: Oauth20ClientRegisterErrorCode,
    /// Human-readable ASCII text providing additional information about the
    /// rejected registration.
    pub error_description: Option<String>,
}

/// Parses error params from JSON bytes.
impl TryFrom<&[u8]> for Oauth20ClientRegisterErrorParams {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The error code of the [`Oauth20ClientRegisterErrorParams`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oauth20ClientRegisterErrorCode {
    /// The value of one or more redirection URIs is invalid.
    InvalidRedirectUri,
    /// The value of one of the client metadata fields is invalid and the server
    /// has rejected this request.
    InvalidClientMetadata,
    /// The software statement presented is invalid.
    InvalidSoftwareStatement,
    /// The software statement presented is not approved for use by this
    /// authorization server.
    UnapprovedSoftwareStatement,
    /// A code this module does not know (servers may extend the registry).
    #[serde(other)]
    Unknown,
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20ClientRegisterError {
    /// The HTTP request could not be sent.
    #[error(transparent)]
    SendHttpRegister(#[from] Http11SendError),
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
pub enum Oauth20ClientRegisterResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20ClientRegisterResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20ClientRegisterError),
}

/// The I/O-free coroutine to register a client dynamically.
///
/// This coroutine sends the client metadata to the registration endpoint
/// (advertised by the RFC 8414 server metadata) and receives either the issued
/// client information or an error response. A public client registers with
/// `token_endpoint_auth_method: none` and needs no secret nor any provider
/// console.
pub struct Oauth20ClientRegister {
    send: Http11Send,
}

impl Oauth20ClientRegister {
    /// Creates a new I/O-free coroutine to register a client.
    pub fn new(
        request: HttpRequest,
        params: &Oauth20ClientRegisterParams,
    ) -> Result<Self, serde_json::Error> {
        debug!("prepare client registration request");
        trace!("url: {}", request.url);

        let request = request
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(serde_json::to_vec(params)?);

        Ok(Self {
            send: Http11Send::new(request),
        })
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20ClientRegisterResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                debug!("received client registration response");
                trace!("status: {}", *response.status);

                match Oauth20ClientInformation::try_from(response.body.as_slice()) {
                    Ok(client) => Oauth20ClientRegisterResult::Ok(Ok(client)),
                    Err(err) => Oauth20ClientRegisterResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                debug!("received client registration error response");
                trace!("status: {}", *response.status);

                match Oauth20ClientRegisterErrorParams::try_from(response.body.as_slice()) {
                    Ok(err) => Oauth20ClientRegisterResult::Ok(Err(err)),
                    Err(err) => Oauth20ClientRegisterResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20ClientRegisterResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20ClientRegisterResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20ClientRegisterResult::Err(Oauth20ClientRegisterError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => Oauth20ClientRegisterResult::Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use crate::rfc7591::register::*;

    #[test]
    fn params_serialize_without_empty_fields() {
        let params = Oauth20ClientRegisterParams {
            redirect_uris: vec![String::from("http://127.0.0.1/redirect")],
            token_endpoint_auth_method: Some(String::from("none")),
            grant_types: vec![
                String::from("authorization_code"),
                String::from("refresh_token"),
            ],
            client_name: Some(String::from("Cardamum")),
            ..Default::default()
        };

        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""token_endpoint_auth_method":"none""#));
        assert!(!json.contains("software_id"));
        assert!(!json.contains("response_types"));
    }

    #[test]
    fn responses_parse_both_outcomes() {
        let created = br#"{"client_id": "abc", "client_id_issued_at": 1720000000}"#;
        let client = Oauth20ClientInformation::try_from(created.as_slice()).unwrap();
        assert_eq!(client.client_id, "abc");
        assert!(client.client_secret.is_none());

        let rejected =
            br#"{"error": "invalid_redirect_uri", "error_description": "loopback only"}"#;
        let err = Oauth20ClientRegisterErrorParams::try_from(rejected.as_slice()).unwrap();
        assert_eq!(
            err.error,
            Oauth20ClientRegisterErrorCode::InvalidRedirectUri
        );

        let unknown = br#"{"error": "not_in_the_registry"}"#;
        let err = Oauth20ClientRegisterErrorParams::try_from(unknown.as_slice()).unwrap();
        assert_eq!(err.error, Oauth20ClientRegisterErrorCode::Unknown);
    }
}
