use std::borrow::Cow;

use http::{header::CONTENT_TYPE, request};
use io_http::v1_1::coroutines::send::{SendHttp, SendHttpError, SendHttpResult};
use io_stream::io::StreamIo;
use thiserror::Error;
use url::form_urlencoded::Serializer;

use crate::v2_0::issue_access_token::{
    AccessTokenResponse, IssueAccessTokenErrorParams, IssueAccessTokenSuccessParams,
};

#[cfg(feature = "pkce")]
use super::pkce::PkceCodeVerifier;

pub struct AccessTokenRequestParams<'a> {
    pub code: Cow<'a, str>,
    pub redirect_uri: Option<Cow<'a, str>>,
    pub client_id: Cow<'a, str>,
    #[cfg(feature = "pkce")]
    pub pkce_code_verifier: Option<Cow<'a, PkceCodeVerifier>>,
}

impl<'a> AccessTokenRequestParams<'a> {
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

        #[cfg(feature = "pkce")]
        if let Some(verifier) = &self.pkce_code_verifier {
            let verifier = String::from_utf8_lossy(verifier.expose());
            serializer.append_pair("code_verifier", &verifier);
        }

        serializer
    }
}

impl ToString for AccessTokenRequestParams<'_> {
    fn to_string(&self) -> String {
        self.to_form_url_encoded_serializer().finish()
    }
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum RequestOauth2AccessTokenError {
    #[error(transparent)]
    SendHttpRequest(#[from] SendHttpError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
}

/// Send result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum RequestOauth2AccessTokenResult {
    /// The coroutine has successfully terminated its execution.
    Ok(AccessTokenResponse),
    /// The coroutine wants stream I/O.
    Io(StreamIo),
    /// The coroutine encountered an error.
    Err(RequestOauth2AccessTokenError),
}

/// The authorization code grant type is used to obtain both access
/// tokens and refresh tokens and is optimized for confidential
/// clients. Since this is a redirection-based flow, the client must
/// be capable of interacting with the resource owner's user-agent
/// (typically a web browser) and capable of receiving incoming
/// requests (via redirection) from the authorization server.
///
/// Refs: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
#[derive(Debug)]
pub struct RequestOauth2AccessToken(SendHttp);

impl RequestOauth2AccessToken {
    pub fn new(
        request: request::Builder,
        body: AccessTokenRequestParams<'_>,
    ) -> http::Result<Self> {
        let request = request
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes())?;

        Ok(Self(SendHttp::new(request)))
    }

    pub fn resume(&mut self, input: Option<StreamIo>) -> RequestOauth2AccessTokenResult {
        let response = match self.0.resume(input) {
            SendHttpResult::Ok(result) => result.response,
            SendHttpResult::Io(io) => return RequestOauth2AccessTokenResult::Io(io),
            SendHttpResult::Err(err) => return RequestOauth2AccessTokenResult::Err(err.into()),
        };

        let body = response.body().as_slice();

        if !response.status().is_success() {
            return match IssueAccessTokenErrorParams::try_from(body) {
                Ok(res) => RequestOauth2AccessTokenResult::Ok(Err(res)),
                Err(err) => RequestOauth2AccessTokenResult::Err(err.into()),
            };
        }

        match IssueAccessTokenSuccessParams::try_from(body) {
            Ok(res) => RequestOauth2AccessTokenResult::Ok(Ok(res)),
            Err(err) => RequestOauth2AccessTokenResult::Err(err.into()),
        }
    }
}
