//! JWT bearer authorization grant (RFC 7523 section 2.1).
//!
//! Exchanges a signed JWT assertion for an access token with
//! `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`: the
//! assertion itself is the authorization grant, no end user round
//! trip involved. This is the Google service account flow: `iss` is
//! the service account email, `aud` the token endpoint, the requested
//! scopes ride in the `scope` claim, and `sub` names the impersonated
//! user for domain-wide delegation. The assertion comes from the
//! assertion sibling module, or from any external signer.
//!
//! The coroutine follows the client credentials naming
//! (`Oauth20ClientCredentialsRequest`): the target is the JWT bearer
//! grant, the verb the token request performed with it.
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
//! use io_oauth::rfc7523::auth_grant::*;
//! use url::Url;
//!
//! let token_url = Url::parse("https://oauth2.googleapis.com/token").unwrap();
//! let request = HttpRequest {
//!     method: "POST".into(),
//!     url: token_url.clone(),
//!     headers: Vec::new(),
//!     body: Vec::new(),
//! }
//! .header("Host", token_url.host_str().unwrap());
//!
//! let params = Oauth20JwtBearerGrantRequestParams {
//!     assertion: "eyJhbGciOiJSUzI1NiJ9.….…".into(),
//!     scope: Default::default(),
//! };
//!
//! let mut stream = TcpStream::connect("oauth2.googleapis.com:443").unwrap();
//! let mut coroutine = Oauth20JwtBearerGrantRequest::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20JwtBearerGrantRequestResult::Ok(res) => break res,
//!         Oauth20JwtBearerGrantRequestResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20JwtBearerGrantRequestResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20JwtBearerGrantRequestResult::Err(err) => panic!("{err}"),
//!     }
//! };
//! # let _ = response;
//! ```

use alloc::{borrow::Cow, collections::BTreeSet, string::String, vec::Vec};

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

/// The JWT bearer grant request parameters.
///
/// The assertion is the grant: no client secret nor other client
/// authentication rides along. The optional `scope` request parameter
/// stays available for providers reading scopes from the body;
/// Google ignores it and reads the `scope` claim instead.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7523#section-2.1>
#[derive(Debug)]
pub struct Oauth20JwtBearerGrantRequestParams<'a> {
    /// The compact JWS assertion used as the authorization grant.
    pub assertion: SecretString,
    /// The scope of the access request.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub scope: BTreeSet<Cow<'a, str>>,
}

impl<'a> Oauth20JwtBearerGrantRequestParams<'a> {
    /// Serializes the params into the form-urlencoded request body.
    // SAFETY: exposes the assertion
    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");

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

        serializer.append_pair("assertion", self.assertion.expose_secret());

        serializer
    }

    /// Builds the form-urlencoded request body.
    // SAFETY: exposes the assertion
    pub fn to_body(&self) -> Vec<u8> {
        self.to_serializer().finish().into_bytes()
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20JwtBearerGrantRequestError {
    /// The HTTP request could not be sent.
    #[error(transparent)]
    SendHttpRequest(#[from] Http11SendError),
    /// The HTTP response could not be parsed.
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    /// The server answered an error status without an OAuth error body.
    #[error("Unexpected JWT bearer grant status {0}")]
    Status(u16),
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
pub enum Oauth20JwtBearerGrantRequestResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20JwtBearerGrantRequestError),
}

/// The I/O-free coroutine to request an access token with the JWT
/// bearer authorization grant.
///
/// Like the client credentials grant, no refresh token is issued: the
/// client signs a fresh assertion and repeats the request on expiry.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7523#section-2.1>
pub struct Oauth20JwtBearerGrantRequest {
    send: Http11Send,
}

impl Oauth20JwtBearerGrantRequest {
    /// Creates the coroutine to request a JWT bearer grant access token.
    pub fn new(request: HttpRequest, body: Oauth20JwtBearerGrantRequestParams<'_>) -> Self {
        debug!("prepare JWT bearer grant request");
        trace!("url: {}", request.url);

        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_body());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20JwtBearerGrantRequestResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                debug!("received JWT bearer grant response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20JwtBearerGrantRequestResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20JwtBearerGrantRequestResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                debug!("received JWT bearer grant error response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20JwtBearerGrantRequestResult::Ok(Err(res)),
                    Err(_) => {
                        let err = Oauth20JwtBearerGrantRequestError::Status(*response.status);
                        Oauth20JwtBearerGrantRequestResult::Err(err)
                    }
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20JwtBearerGrantRequestResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20JwtBearerGrantRequestResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20JwtBearerGrantRequestResult::Err(
                    Oauth20JwtBearerGrantRequestError::Redirect {
                        url,
                        code: *response.status,
                    },
                )
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20JwtBearerGrantRequestResult::Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use io_http::rfc9110::request::HttpRequest;
    use url::Url;

    use crate::rfc7523::auth_grant::*;

    #[test]
    fn an_error_status_without_oauth_body_returns_its_status() {
        let request = HttpRequest {
            method: "POST".into(),
            url: Url::parse("https://example.test/token").unwrap(),
            headers: Vec::new(),
            body: Vec::new(),
        };

        let params = Oauth20JwtBearerGrantRequestParams {
            assertion: "aaa.bbb.ccc".into(),
            scope: Default::default(),
        };

        let mut coroutine = Oauth20JwtBearerGrantRequest::new(request, params);
        let response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        let mut arg = None;

        let result = loop {
            match coroutine.resume(arg.take()) {
                Oauth20JwtBearerGrantRequestResult::WantsWrite(_) => {}
                Oauth20JwtBearerGrantRequestResult::WantsRead => arg = Some(response.as_slice()),
                result => break result,
            }
        };

        assert!(matches!(
            result,
            Oauth20JwtBearerGrantRequestResult::Err(Oauth20JwtBearerGrantRequestError::Status(503))
        ));
    }

    #[test]
    fn params_serialize_to_form_body() {
        let params = Oauth20JwtBearerGrantRequestParams {
            assertion: "aaa.bbb.ccc".into(),
            scope: ["https://mail.google.com/".into()].into(),
        };

        assert_eq!(
            String::from_utf8(params.to_body()).unwrap(),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
             &scope=https%3A%2F%2Fmail.google.com%2F\
             &assertion=aaa.bbb.ccc"
        );
    }

    #[test]
    fn params_serialize_without_empty_scope() {
        let params = Oauth20JwtBearerGrantRequestParams {
            assertion: "aaa.bbb.ccc".into(),
            scope: Default::default(),
        };

        assert_eq!(
            String::from_utf8(params.to_body()).unwrap(),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
             &assertion=aaa.bbb.ccc"
        );
    }
}
