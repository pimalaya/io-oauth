//! Module dedicated to the section 6: Refreshing an Access Token.
//!
//! Refs: https://datatracker.ietf.org/doc/html/rfc6749#section-6

use std::{borrow::Cow, collections::HashSet};

use http::{header::CONTENT_TYPE, request};
use io_http::v1_1::coroutines::send::{SendHttp, SendHttpError, SendHttpResult};
use io_stream::io::StreamIo;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use url::form_urlencoded::Serializer;

use super::issue_access_token::{
    AccessTokenResponse, IssueAccessTokenErrorParams, IssueAccessTokenSuccessParams,
};

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum RefreshOauth2AccessTokenError {
    #[error(transparent)]
    SendHttpRefresh(#[from] SendHttpError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
}

/// Send result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum RefreshOauth2AccessTokenResult {
    /// The coroutine has successfully terminated its execution.
    Ok(AccessTokenResponse),
    /// The coroutine wants stream I/O.
    Io(StreamIo),
    /// The coroutine encountered an error.
    Err(RefreshOauth2AccessTokenError),
}

/// The I/O-free coroutine to refresh an access token.
///
/// This coroutine sends the refresh access token HTTP request to the
/// token endpoint and receives either a successful or an error HTTP
/// response.
///
/// Refs: [`AccessTokenResponse`]
pub struct RefreshOauth2AccessToken(SendHttp);

impl RefreshOauth2AccessToken {
    /// Creates a new I/O-free coroutine to refresh an access token.
    pub fn new(
        request: request::Builder,
        body: RefreshAccessTokenParams<'_>,
    ) -> http::Result<Self> {
        let request = request
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes())?;

        let send = SendHttp::new(request);
        Ok(Self(send))
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<StreamIo>) -> RefreshOauth2AccessTokenResult {
        let response = match self.0.resume(arg) {
            SendHttpResult::Ok(result) => result.response,
            SendHttpResult::Io(io) => return RefreshOauth2AccessTokenResult::Io(io),
            SendHttpResult::Err(err) => return RefreshOauth2AccessTokenResult::Err(err.into()),
        };

        let body = response.body().as_slice();

        if !response.status().is_success() {
            return match IssueAccessTokenErrorParams::try_from(body) {
                Ok(res) => RefreshOauth2AccessTokenResult::Ok(Err(res)),
                Err(err) => RefreshOauth2AccessTokenResult::Err(err.into()),
            };
        }

        match IssueAccessTokenSuccessParams::try_from(body) {
            Ok(res) => RefreshOauth2AccessTokenResult::Ok(Ok(res)),
            Err(err) => RefreshOauth2AccessTokenResult::Err(err.into()),
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
/// Refs: https://datatracker.ietf.org/doc/html/rfc6749#section-6
#[derive(Debug)]
pub struct RefreshAccessTokenParams<'a> {
    pub client_id: String,
    pub refresh_token: SecretString,
    pub scopes: HashSet<Cow<'a, str>>,
}

impl<'a> RefreshAccessTokenParams<'a> {
    pub fn new(client_id: impl ToString, refresh_token: impl Into<SecretString>) -> Self {
        Self {
            client_id: client_id.to_string(),
            refresh_token: refresh_token.into(),
            scopes: HashSet::new(),
        }
    }

    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "refresh_token");
        serializer.append_pair("client_id", &self.client_id);
        serializer.append_pair("refresh_token", &self.refresh_token.expose_secret());

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

impl ToString for RefreshAccessTokenParams<'_> {
    fn to_string(&self) -> String {
        self.to_serializer().finish()
    }
}
