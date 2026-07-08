//! Module dedicated to the section 6: Refreshing an Access Token.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-6>

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
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::{Url, form_urlencoded::Serializer};

use crate::v2_0::issue_access_token::{
    Oauth20AccessTokenResponse, Oauth20IssueAccessTokenErrorParams,
    Oauth20IssueAccessTokenSuccessParams, parse_http_date,
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20RefreshAccessTokenError {
    #[error(transparent)]
    SendHttpRefresh(#[from] Http11SendError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    #[error("Unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
}

/// Result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum Oauth20RefreshAccessTokenResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20AccessTokenResponse),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the
    /// socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20RefreshAccessTokenError),
}

/// The I/O-free coroutine to refresh an access token.
///
/// This coroutine sends the refresh access token HTTP request to the
/// token endpoint and receives either a successful or an error HTTP
/// response.
///
/// Refs: [`Oauth20AccessTokenResponse`]
pub struct Oauth20RefreshAccessToken {
    send: Http11Send,
}

impl Oauth20RefreshAccessToken {
    /// Creates a new I/O-free coroutine to refresh an access token.
    pub fn new(request: HttpRequest, body: Oauth20RefreshAccessTokenParams<'_>) -> Self {
        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes());

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20RefreshAccessTokenResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20IssueAccessTokenSuccessParams::try_from(response.body.as_slice()) {
                    Ok(mut res) => {
                        res.issued_at = response.header("date").and_then(parse_http_date);
                        Oauth20RefreshAccessTokenResult::Ok(Ok(res))
                    }
                    Err(err) => Oauth20RefreshAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                match Oauth20IssueAccessTokenErrorParams::try_from(response.body.as_slice()) {
                    Ok(res) => Oauth20RefreshAccessTokenResult::Ok(Err(res)),
                    Err(err) => Oauth20RefreshAccessTokenResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20RefreshAccessTokenResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20RefreshAccessTokenResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20RefreshAccessTokenResult::Err(Oauth20RefreshAccessTokenError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20RefreshAccessTokenResult::Err(err.into())
            }
        }
    }
}

/// The refresh access token request parameters.
///
/// If the authorization server issued a refresh token to the client,
/// the client makes a refresh request to the token endpoint by adding
/// the following parameters using the
/// "application/x-www-form-urlencoded" format with a character
/// encoding of UTF-8 in the HTTP request entity-body.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-6>
#[derive(Debug)]
pub struct Oauth20RefreshAccessTokenParams<'a> {
    pub client_id: String,
    /// Secret issued alongside the client id, when the server requires
    /// it in the exchange (Google does for its desktop-type clients,
    /// even though such installed apps cannot keep it confidential).
    pub client_secret: Option<SecretString>,
    pub refresh_token: SecretString,
    pub scopes: BTreeSet<Cow<'a, str>>,
}

impl<'a> Oauth20RefreshAccessTokenParams<'a> {
    pub fn new(client_id: impl ToString, refresh_token: impl Into<SecretString>) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: None,
            refresh_token: refresh_token.into(),
            scopes: BTreeSet::new(),
        }
    }

    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "refresh_token");
        serializer.append_pair("client_id", &self.client_id);

        if let Some(secret) = &self.client_secret {
            serializer.append_pair("client_secret", secret.expose_secret());
        }

        serializer.append_pair("refresh_token", self.refresh_token.expose_secret());

        if !self.scopes.is_empty() {
            let mut scope = String::new();
            let mut glue = "";

            for token in &self.scopes {
                scope.push_str(glue);
                scope.push_str(token);
                glue = " ";
            }

            serializer.append_pair("scope", &scope);
        }

        serializer
    }
}

impl fmt::Display for Oauth20RefreshAccessTokenParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_serializer().finish())
    }
}
