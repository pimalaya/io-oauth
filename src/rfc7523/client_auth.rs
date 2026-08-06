//! JWT client authentication on the client credentials grant
//! (RFC 7523 section 2.2).
//!
//! Requests an access token with `grant_type=client_credentials`,
//! authenticating the client with a signed JWT assertion
//! (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`)
//! instead of a client secret. This is the Microsoft certificate
//! credentials flow: `client_id` rides in the body, the assertion's
//! `iss` and `sub` are both the application (client) id, its `aud` is
//! the token endpoint, its header carries the certificate `x5t`
//! thumbprint, and `scope` is the resource `.default` scope. The
//! assertion comes from the assertion sibling module, or from any
//! external signer.
//!
//! The coroutine follows the client credentials naming
//! (`Oauth20ClientCredentialsRequest`), prefixed by the JWT bearer
//! family it belongs to.
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
//! use io_oauth::rfc7523::client_auth::*;
//! use url::Url;
//!
//! let token_url =
//!     Url::parse("https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token").unwrap();
//! let request = HttpRequest {
//!     method: "POST".into(),
//!     url: token_url.clone(),
//!     headers: Vec::new(),
//!     body: Vec::new(),
//! }
//! .header("Host", token_url.host_str().unwrap());
//!
//! let params = Oauth20JwtBearerClientCredentialsRequestParams {
//!     client_id: Some("app-client-id".into()),
//!     scope: ["https://graph.microsoft.com/.default".into()].into(),
//!     client_assertion: "eyJhbGciOiJSUzI1NiJ9.….…".into(),
//! };
//!
//! let mut stream = TcpStream::connect("login.microsoftonline.com:443").unwrap();
//! let mut coroutine = Oauth20JwtBearerClientCredentialsRequest::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20JwtBearerClientCredentialsRequestResult::Ok(res) => break res,
//!         Oauth20JwtBearerClientCredentialsRequestResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20JwtBearerClientCredentialsRequestResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20JwtBearerClientCredentialsRequestResult::Err(err) => panic!("{err}"),
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
use log::{debug, trace};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::{Url, form_urlencoded::Serializer};

use crate::rfc6749::issue_access_token::{
    Oauth20AccessTokenErrorParams, Oauth20AccessTokenResponse, Oauth20AccessTokenSuccessParams,
    parse_http_date,
};

/// The JWT-authenticated client credentials request parameters.
///
/// The client authenticates through the assertion, so no Basic
/// `Authorization` header nor client secret is involved. `client_id`
/// is optional per the spec (the assertion's `iss` already identifies
/// the client) but Microsoft requires it in the body.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7523#section-2.2>
#[derive(Debug)]
pub struct Oauth20JwtBearerClientCredentialsRequestParams<'a> {
    /// The client identifier.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.2>
    pub client_id: Option<Cow<'a, str>>,
    /// The scope of the access request.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub scope: BTreeSet<Cow<'a, str>>,
    /// The compact JWS assertion authenticating the client.
    pub client_assertion: SecretString,
}

impl<'a> Oauth20JwtBearerClientCredentialsRequestParams<'a> {
    /// Serializes the params into the form-urlencoded request body.
    // SAFETY: exposes the client assertion
    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "client_credentials");

        if let Some(client_id) = &self.client_id {
            serializer.append_pair("client_id", client_id);
        }

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

        serializer.append_pair(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        );
        serializer.append_pair("client_assertion", self.client_assertion.expose_secret());

        serializer
    }
}

impl fmt::Display for Oauth20JwtBearerClientCredentialsRequestParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_serializer().finish())
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20JwtBearerClientCredentialsRequestError {
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
pub enum Oauth20JwtBearerClientCredentialsRequestResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20JwtBearerClientCredentialsRequestError),
}

/// The I/O-free coroutine to request an access token with the client
/// credentials grant authenticated by a JWT client assertion.
///
/// Like the secret-authenticated variant, no refresh token is issued:
/// the client signs a fresh assertion and repeats the request on
/// expiry.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7523#section-2.2>
pub struct Oauth20JwtBearerClientCredentialsRequest {
    send: Http11Send,
}

impl Oauth20JwtBearerClientCredentialsRequest {
    /// Creates the coroutine to request a JWT-authenticated client
    /// credentials access token.
    pub fn new(
        request: HttpRequest,
        body: Oauth20JwtBearerClientCredentialsRequestParams<'_>,
    ) -> Self {
        debug!("prepare JWT-authenticated client credentials request");
        trace!("url: {}", request.url);

        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20JwtBearerClientCredentialsRequestResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                debug!("received JWT-authenticated client credentials response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20JwtBearerClientCredentialsRequestResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20JwtBearerClientCredentialsRequestResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                debug!("received JWT-authenticated client credentials error response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20JwtBearerClientCredentialsRequestResult::Ok(Err(res)),
                    Err(err) => Oauth20JwtBearerClientCredentialsRequestResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20JwtBearerClientCredentialsRequestResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20JwtBearerClientCredentialsRequestResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20JwtBearerClientCredentialsRequestResult::Err(
                    Oauth20JwtBearerClientCredentialsRequestError::Redirect {
                        url,
                        code: *response.status,
                    },
                )
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20JwtBearerClientCredentialsRequestResult::Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use crate::rfc7523::client_auth::*;

    #[test]
    fn params_serialize_to_form_body() {
        let params = Oauth20JwtBearerClientCredentialsRequestParams {
            client_id: Some("app-id".into()),
            scope: ["https://graph.microsoft.com/.default".into()].into(),
            client_assertion: "aaa.bbb.ccc".into(),
        };

        assert_eq!(
            params.to_string(),
            "grant_type=client_credentials\
             &client_id=app-id\
             &scope=https%3A%2F%2Fgraph.microsoft.com%2F.default\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion=aaa.bbb.ccc"
        );
    }

    #[test]
    fn params_serialize_without_empty_fields() {
        let params = Oauth20JwtBearerClientCredentialsRequestParams {
            client_id: None,
            scope: Default::default(),
            client_assertion: "aaa.bbb.ccc".into(),
        };

        assert_eq!(
            params.to_string(),
            "grant_type=client_credentials\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
             &client_assertion=aaa.bbb.ccc"
        );
    }
}
