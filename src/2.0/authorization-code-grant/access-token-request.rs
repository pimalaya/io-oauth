use std::borrow::Cow;

use http::{header::CONTENT_TYPE, request};
use io_http::v1_1::coroutines::Send;
use io_stream::Io;
use url::form_urlencoded::Serializer;

use crate::v2_0::issue_access_token::{
    AccessTokenErrorResponse, AccessTokenResponse, AccessTokenSuccessfulResponse,
};

pub struct AccessTokenRequestParams<'a> {
    pub code: Cow<'a, str>,
    pub redirect_uri: Cow<'a, str>,
    pub client_id: Cow<'a, str>,
}

impl<'a> AccessTokenRequestParams<'a> {
    pub fn new(
        code: impl Into<Cow<'a, str>>,
        redirect_uri: impl Into<Cow<'a, str>>,
        client_id: impl Into<Cow<'a, str>>,
    ) -> Self {
        Self {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            client_id: client_id.into(),
        }
    }

    pub fn to_serializer(&self) -> Serializer<'a, String> {
        let mut serializer = Serializer::new(String::new());

        serializer.append_pair("grant_type", "authorization_code");
        serializer.append_pair("code", &self.code);
        serializer.append_pair("redirect_uri", &self.redirect_uri);
        serializer.append_pair("client_id", &self.client_id);

        serializer
    }
}

impl ToString for AccessTokenRequestParams<'_> {
    fn to_string(&self) -> String {
        self.to_serializer().finish()
    }
}

/// The authorization code grant type is used to obtain both access
/// tokens and refresh tokens and is optimized for confidential
/// clients. Since this is a redirection-based flow, the client must
/// be capable of interacting with the resource owner's user-agent
/// (typically a web browser) and capable of receiving incoming
/// requests (via redirection) from the authorization server.
///
/// Refs: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
///
#[derive(Debug)]
pub struct SendAccessTokenRequest(Send);

impl SendAccessTokenRequest {
    pub fn new(
        request: request::Builder,
        body: AccessTokenRequestParams<'_>,
    ) -> http::Result<Self> {
        let request = request
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.to_string().into_bytes())?;

        Ok(Self(Send::new(request)))
    }

    pub fn resume(
        &mut self,
        input: Option<Io>,
    ) -> Result<serde_json::Result<AccessTokenResponse>, Io> {
        let response = self.0.resume(input)?;
        let body = response.body().as_slice();

        if response.status().is_success() {
            match AccessTokenSuccessfulResponse::try_from(body) {
                Ok(res) => Ok(Ok(Ok(res))),
                Err(err) => Ok(Err(err)),
            }
        } else {
            match AccessTokenErrorResponse::try_from(body) {
                Ok(res) => Ok(Ok(Err(res))),
                Err(err) => Ok(Err(err)),
            }
        }
    }
}
