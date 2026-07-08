//! Module dedicated to OAuth 2.0 Authorization Server Metadata.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc8414>

use alloc::{format, string::String, vec::Vec};

use io_http::{
    coroutine::*,
    rfc9110::{
        request::HttpRequest,
        send::{HttpSendOutput, HttpSendYield},
    },
    rfc9112::send::{Http11Send, Http11SendError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// The metadata describing an authorization server's configuration.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc8414#section-2>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Oauth20ServerMetadata {
    /// The authorization server's issuer identifier.
    pub issuer: Url,

    /// URL of the authorization endpoint (RFC 6749 §3.1).
    pub authorization_endpoint: Option<Url>,

    /// URL of the token endpoint (RFC 6749 §3.2).
    pub token_endpoint: Option<Url>,

    /// URL of the JWK Set document (RFC 7517).
    pub jwks_uri: Option<Url>,

    /// URL of the dynamic client registration endpoint (RFC 7591).
    pub registration_endpoint: Option<Url>,

    /// The scope values this server supports.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// The `response_type` values this server supports.
    #[serde(default)]
    pub response_types_supported: Vec<String>,

    /// The `response_mode` values this server supports.
    #[serde(default)]
    pub response_modes_supported: Vec<String>,

    /// The grant types this server supports.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,

    /// The client authentication methods the token endpoint supports
    /// (`none` means public clients need no secret).
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// URL of the developer documentation.
    pub service_documentation: Option<Url>,

    /// URL of the token revocation endpoint (RFC 7009).
    pub revocation_endpoint: Option<Url>,

    /// URL of the token introspection endpoint (RFC 7662).
    pub introspection_endpoint: Option<Url>,

    /// The PKCE code challenge methods this server supports
    /// (RFC 7636).
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,

    /// URL of the device authorization endpoint (RFC 8628 §4).
    pub device_authorization_endpoint: Option<Url>,
}

impl Oauth20ServerMetadata {
    /// Builds the metadata's well-known URL for an issuer, inserting
    /// the well-known path between host and issuer path components.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8414#section-3.1>
    pub fn well_known_url(issuer: &Url) -> Url {
        insert_well_known(issuer, "/.well-known/oauth-authorization-server")
    }

    /// Builds the OpenID Connect Discovery compatibility URL for an
    /// issuer, appending the well-known path after the issuer path.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8414#section-5>
    pub fn openid_well_known_url(issuer: &Url) -> Url {
        let mut url = issuer.clone();
        let path = issuer.path().trim_end_matches('/');
        url.set_path(&format!("{path}/.well-known/openid-configuration"));
        url.set_query(None);
        url.set_fragment(None);
        url
    }
}

/// Deserializes server metadata from JSON bytes.
impl TryFrom<&[u8]> for Oauth20ServerMetadata {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Inserts a well-known path between the host and path components of
/// a URL, per the RFC 8414 §3.1 transformation (shared with RFC 9728
/// §3.1, which uses the same rule for resources).
pub(crate) fn insert_well_known(url: &Url, well_known: &str) -> Url {
    let mut transformed = url.clone();
    let path = url.path().trim_end_matches('/');
    transformed.set_path(&format!("{well_known}{path}"));
    transformed.set_query(None);
    transformed.set_fragment(None);
    transformed
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20FetchServerMetadataError {
    #[error(transparent)]
    SendHttpFetch(#[from] Http11SendError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    #[error("Unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
    #[error("Unexpected status {code} fetching server metadata")]
    Status { code: u16 },
}

/// Result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum Oauth20FetchServerMetadataResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20ServerMetadata),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the
    /// socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20FetchServerMetadataError),
}

/// The I/O-free coroutine to fetch authorization server metadata.
///
/// This coroutine sends a GET request to the well-known metadata URL
/// (see [`Oauth20ServerMetadata::well_known_url`], falling back to
/// [`Oauth20ServerMetadata::openid_well_known_url`] on a rebuilt
/// coroutine when the server only publishes the OpenID Connect
/// Discovery document) and receives the JSON metadata.
pub struct Oauth20FetchServerMetadata {
    send: Http11Send,
}

impl Oauth20FetchServerMetadata {
    /// Creates a new I/O-free coroutine to fetch server metadata.
    pub fn new(request: HttpRequest) -> Self {
        let request = request.header("Accept", "application/json");

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20FetchServerMetadataResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20ServerMetadata::try_from(response.body.as_slice()) {
                    Ok(metadata) => Oauth20FetchServerMetadataResult::Ok(metadata),
                    Err(err) => Oauth20FetchServerMetadataResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                Oauth20FetchServerMetadataResult::Err(Oauth20FetchServerMetadataError::Status {
                    code: *response.status,
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20FetchServerMetadataResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20FetchServerMetadataResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20FetchServerMetadataResult::Err(Oauth20FetchServerMetadataError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20FetchServerMetadataResult::Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::v2_0::rfc8414::server_metadata::Oauth20ServerMetadata;

    #[test]
    fn well_known_urls_follow_the_transformation_rules() {
        let bare: Url = "https://example.com".parse().unwrap();
        assert_eq!(
            Oauth20ServerMetadata::well_known_url(&bare).as_str(),
            "https://example.com/.well-known/oauth-authorization-server",
        );
        assert_eq!(
            Oauth20ServerMetadata::openid_well_known_url(&bare).as_str(),
            "https://example.com/.well-known/openid-configuration",
        );

        // RFC 8414 §3.1: path components insert AFTER the well-known
        // segment; the OpenID compatibility form appends instead.
        let issuer: Url = "https://example.com/issuer1".parse().unwrap();
        assert_eq!(
            Oauth20ServerMetadata::well_known_url(&issuer).as_str(),
            "https://example.com/.well-known/oauth-authorization-server/issuer1",
        );
        assert_eq!(
            Oauth20ServerMetadata::openid_well_known_url(&issuer).as_str(),
            "https://example.com/issuer1/.well-known/openid-configuration",
        );
    }

    #[test]
    fn metadata_parses_a_minimal_document() {
        let json = br#"{
            "issuer": "https://api.example.com",
            "registration_endpoint": "https://api.example.com/oauth/register",
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"]
        }"#;

        let metadata = Oauth20ServerMetadata::try_from(json.as_slice()).unwrap();
        assert_eq!(metadata.issuer.as_str(), "https://api.example.com/");
        assert!(metadata.registration_endpoint.is_some());
        assert_eq!(metadata.token_endpoint_auth_methods_supported, ["none"]);
        assert!(metadata.scopes_supported.is_empty());
    }
}
