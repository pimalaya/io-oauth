use std::borrow::Cow;

use http::{header::CONTENT_TYPE, request};
use io_http::v1_1::coroutines::Send;
use io_stream::Io;
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
            match IssueAccessTokenSuccessParams::try_from(body) {
                Ok(res) => Ok(Ok(Ok(res))),
                Err(err) => Ok(Err(err)),
            }
        } else {
            match IssueAccessTokenErrorParams::try_from(body) {
                Ok(res) => Ok(Ok(Err(res))),
                Err(err) => Ok(Err(err)),
            }
        }
    }
}
