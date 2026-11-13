//! Access token request (RFC 6749 section 4.1.3).
//!
//! Exchanges an authorization code for an access token against the
//! token endpoint. Consumed by the authorization code grant, next to
//! the auth request and auth response modules.
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
//! use io_oauth::rfc6749::access_token_request::*;
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
//! let params = Oauth20AccessTokenRequestParams {
//!     code: "the-authorization-code".into(),
//!     redirect_uri: None,
//!     client_id: "client-id".into(),
//!     client_secret: None,
//!     pkce_code_verifier: None,
//!     resource: Vec::new(),
//! };
//!
//! let mut stream = TcpStream::connect("example.com:443").unwrap();
//! let mut coroutine = Oauth20AccessTokenRequest::new(request, params);
//! let mut arg: Option<&[u8]> = None;
//! let mut buf = [0u8; 4096];
//!
//! let response = loop {
//!     match coroutine.resume(arg.take()) {
//!         Oauth20AccessTokenRequestResult::Ok(res) => break res,
//!         Oauth20AccessTokenRequestResult::WantsRead => {
//!             let n = stream.read(&mut buf).unwrap();
//!             arg = Some(&buf[..n]);
//!         }
//!         Oauth20AccessTokenRequestResult::WantsWrite(bytes) => {
//!             stream.write_all(&bytes).unwrap();
//!         }
//!         Oauth20AccessTokenRequestResult::Err(err) => panic!("{err}"),
//!     }
//! };
//! # let _ = response;
//! ```

use core::fmt;

use alloc::{borrow::Cow, string::String, vec::Vec};

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

use crate::{
    rfc6749::issue_access_token::{
        Oauth20AccessTokenErrorParams, Oauth20AccessTokenResponse, Oauth20AccessTokenSuccessParams,
        parse_http_date,
    },
    rfc7636::pkce::Oauth20PkceCodeVerifier,
};

/// The access token request parameters, exchanging the authorization code.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3>
pub struct Oauth20AccessTokenRequestParams<'a> {
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
    /// The resources the token is meant for, one `resource` parameter each.
    ///
    /// Empty sends none.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8707#section-2.2>
    pub resource: Vec<Url>,
}

impl<'a> Oauth20AccessTokenRequestParams<'a> {
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

        for resource in &self.resource {
            serializer.append_pair("resource", resource.as_str());
        }

        serializer
    }

    /// Builds the form-urlencoded request body.
    // SAFETY: exposes the code, the client secret and the PKCE code verifier
    pub fn to_body(&self) -> Vec<u8> {
        self.to_form_url_encoded_serializer().finish().into_bytes()
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20AccessTokenRequestError {
    /// The HTTP request could not be sent.
    #[error(transparent)]
    SendHttpRequest(#[from] Http11SendError),
    /// The HTTP response could not be parsed.
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    /// The server answered an error status without an OAuth error body.
    #[error("Unexpected access token status {0}")]
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
pub enum Oauth20AccessTokenRequestResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20AccessTokenRequestError),
}

/// The I/O-free coroutine to exchange an authorization code for an access
/// token.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1>
pub struct Oauth20AccessTokenRequest {
    send: Http11Send,
}

impl fmt::Debug for Oauth20AccessTokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oauth20AccessTokenRequest")
            .finish_non_exhaustive()
    }
}

impl Oauth20AccessTokenRequest {
    /// Creates the coroutine to exchange an authorization code.
    pub fn new(request: HttpRequest, body: Oauth20AccessTokenRequestParams<'_>) -> Self {
        debug!("prepare access token request");
        trace!("url: {}", request.url);

        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_body());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20AccessTokenRequestResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                debug!("received access token response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20AccessTokenRequestResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20AccessTokenRequestResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                debug!("received access token error response");
                trace!("status: {}", *response.status);

                match Oauth20AccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20AccessTokenRequestResult::Ok(Err(res)),
                    Err(_) => {
                        let err = Oauth20AccessTokenRequestError::Status(*response.status);
                        Oauth20AccessTokenRequestResult::Err(err)
                    }
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20AccessTokenRequestResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20AccessTokenRequestResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20AccessTokenRequestResult::Err(Oauth20AccessTokenRequestError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20AccessTokenRequestResult::Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use io_http::{
        rfc9110::request::{HttpRequest, HttpRequestError},
        rfc9112::send::Http11SendError,
    };
    use url::Url;

    use crate::rfc6749::{access_token_request::*, issue_access_token::*};

    fn request() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            url: Url::parse("https://example.test/token").unwrap(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn coroutine(code: &'static str) -> Oauth20AccessTokenRequest {
        coroutine_from(request(), code)
    }

    fn coroutine_from(request: HttpRequest, code: &'static str) -> Oauth20AccessTokenRequest {
        let params = Oauth20AccessTokenRequestParams {
            code: code.into(),
            redirect_uri: None,
            client_id: "client".into(),
            client_secret: None,
            pkce_code_verifier: None,
            resource: Vec::new(),
        };

        Oauth20AccessTokenRequest::new(request, params)
    }

    fn exchange(status: &str, body: &str) -> Oauth20AccessTokenRequestResult {
        let len = body.len();
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: {len}\r\n\r\n{body}");
        let mut coroutine = coroutine("code");
        let mut arg = None;

        loop {
            match coroutine.resume(arg.take()) {
                Oauth20AccessTokenRequestResult::WantsWrite(_) => {}
                Oauth20AccessTokenRequestResult::WantsRead => arg = Some(response.as_bytes()),
                result => return result,
            }
        }
    }

    #[test]
    fn a_number_lifetime_is_kept() {
        let body = r#"{"access_token":"t","token_type":"example","expires_in":3600}"#;

        let Oauth20AccessTokenRequestResult::Ok(Ok(res)) = exchange("200 OK", body) else {
            panic!("expected a token");
        };

        assert_eq!(res.token_type, "example");
        assert_eq!(res.expires_in, Some(3600));
    }

    #[test]
    fn a_numeric_string_lifetime_is_accepted() {
        let body = r#"{"access_token":"t","token_type":"Bearer","expires_in":"3600"}"#;

        let Oauth20AccessTokenRequestResult::Ok(Ok(res)) = exchange("200 OK", body) else {
            panic!("expected a token");
        };

        assert_eq!(res.expires_in, Some(3600));
    }

    #[test]
    fn a_missing_token_type_defaults_to_bearer() {
        let body = r#"{"access_token":"t","refresh_token":"r"}"#;

        let Oauth20AccessTokenRequestResult::Ok(Ok(res)) = exchange("200 OK", body) else {
            panic!("expected a token");
        };

        assert_eq!(res.token_type, "Bearer");
        assert_eq!(res.expires_in, None);
    }

    #[test]
    fn an_oauth_error_body_returns_its_code() {
        let result = exchange("400 Bad Request", r#"{"error":"invalid_grant"}"#);

        let Oauth20AccessTokenRequestResult::Ok(Err(err)) = result else {
            panic!("expected an error response");
        };

        assert_eq!(err.error, Oauth20AccessTokenErrorCode::InvalidGrant);
    }

    #[test]
    fn an_error_status_without_oauth_body_returns_its_status() {
        let result = exchange("503 Service Unavailable", "<html>down</html>");

        assert!(matches!(
            result,
            Oauth20AccessTokenRequestResult::Err(Oauth20AccessTokenRequestError::Status(503))
        ));
    }

    #[test]
    fn a_header_value_holding_a_line_break_fails_before_any_write() {
        let request = request().header("X-Tenant", "a\r\nX-Injected: b");
        let mut coroutine = coroutine_from(request, "code");

        let Oauth20AccessTokenRequestResult::Err(err) = coroutine.resume(None) else {
            panic!("expected an error at the first resume");
        };

        let Oauth20AccessTokenRequestError::SendHttpRequest(err) = err else {
            panic!("expected a send error, got {err:?}");
        };

        let name = "X-Tenant".into();
        let expected = HttpRequestError::InvalidHeaderValue(name);
        assert!(matches!(err, Http11SendError::InvalidRequest(err) if err == expected));
    }

    #[test]
    fn debug_hides_the_request_body() {
        let debug = format!("{:?}", coroutine("s3cr3t-code"));
        let bytes = format!("{:?}", b"s3cr3t-code");

        assert!(!debug.contains(bytes.trim_matches(['[', ']'])), "{debug}");
    }

    #[test]
    fn every_resource_is_its_own_body_pair() {
        let params = Oauth20AccessTokenRequestParams {
            code: "code".into(),
            redirect_uri: None,
            client_id: "client".into(),
            client_secret: None,
            pkce_code_verifier: None,
            resource: vec![
                Url::parse("https://api.example.test/jmap").unwrap(),
                Url::parse("https://dav.example.test/").unwrap(),
            ],
        };

        assert_eq!(
            String::from_utf8(params.to_body()).unwrap(),
            "grant_type=authorization_code&code=code&client_id=client\
             &resource=https%3A%2F%2Fapi.example.test%2Fjmap\
             &resource=https%3A%2F%2Fdav.example.test%2F"
        );
    }
}
