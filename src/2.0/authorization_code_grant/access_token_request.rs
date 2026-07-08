//! Module dedicated to the section 4.1.3: Access Token Request.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3>

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

use crate::v2_0::{
    authorization_code_grant::pkce::Oauth20PkceCodeVerifier,
    issue_access_token::{
        Oauth20AccessTokenResponse, Oauth20IssueAccessTokenErrorParams,
        Oauth20IssueAccessTokenSuccessParams, parse_http_date,
    },
};

pub struct Oauth20AccessTokenRequestParams<'a> {
    pub code: Cow<'a, str>,
    pub redirect_uri: Option<Cow<'a, str>>,
    pub client_id: Cow<'a, str>,
    /// Secret issued alongside the client id, when the server requires
    /// it in the exchange (Google does for its desktop-type clients,
    /// even though such installed apps cannot keep it confidential).
    pub client_secret: Option<SecretString>,
    pub pkce_code_verifier: Option<Cow<'a, Oauth20PkceCodeVerifier>>,
}

impl<'a> Oauth20AccessTokenRequestParams<'a> {
    // SAFETY: this function exposes the code and the PKCE code
    // verifier
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

        serializer
    }
}

impl fmt::Display for Oauth20AccessTokenRequestParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_form_url_encoded_serializer().finish())
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20RequestAccessTokenError {
    #[error(transparent)]
    SendHttpRequest(#[from] Http11SendError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    #[error("Unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
}

/// Result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum Oauth20RequestAccessTokenResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the
    /// socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20RequestAccessTokenError),
}

/// The authorization code grant type is used to obtain both access
/// tokens and refresh tokens and is optimized for confidential
/// clients. Since this is a redirection-based flow, the client must
/// be capable of interacting with the resource owner's user-agent
/// (typically a web browser) and capable of receiving incoming
/// requests (via redirection) from the authorization server.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1>
#[derive(Debug)]
pub struct Oauth20RequestAccessToken {
    send: Http11Send,
}

impl Oauth20RequestAccessToken {
    pub fn new(request: HttpRequest, body: Oauth20AccessTokenRequestParams<'_>) -> Self {
        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20RequestAccessTokenResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20IssueAccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20RequestAccessTokenResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20RequestAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                match Oauth20IssueAccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RequestAccessTokenResult::Ok(Err(res)),
                    Err(err) => Oauth20RequestAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20RequestAccessTokenResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20RequestAccessTokenResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20RequestAccessTokenResult::Err(Oauth20RequestAccessTokenError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20RequestAccessTokenResult::Err(err.into())
            }
        }
    }
}
