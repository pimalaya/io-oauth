//! Module dedicated to OAuth 2.0 Protected Resource Metadata.
//!
//! Refs: <https://datatracker.ietf.org/doc/html/rfc9728>

use alloc::{string::String, vec::Vec};

use io_http::{
    coroutine::*,
    rfc9110::{
        challenge::parse_challenges,
        request::HttpRequest,
        send::{HttpSendOutput, HttpSendYield},
    },
    rfc9112::send::{Http11Send, Http11SendError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::v2_0::rfc8414::server_metadata::insert_well_known;

/// The metadata describing a protected resource's configuration,
/// pointing clients at the authorization servers that can issue
/// tokens for it.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc9728#section-2>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Oauth20ResourceMetadata {
    /// The resource's identifier.
    pub resource: Url,

    /// Issuer identifiers of the authorization servers that can be
    /// used with this resource; each resolves to its RFC 8414
    /// metadata.
    #[serde(default)]
    pub authorization_servers: Vec<Url>,

    /// URL of the resource's JWK Set document (RFC 7517).
    pub jwks_uri: Option<Url>,

    /// The scope values used in authorization requests to access this
    /// resource.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// The bearer token presentation methods this resource supports
    /// (`header`, `body`, `query`; RFC 6750).
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,

    /// Human-readable name of the resource.
    pub resource_name: Option<String>,

    /// URL of the resource's developer documentation.
    pub resource_documentation: Option<Url>,

    /// URL of the resource's usage policy.
    pub resource_policy_uri: Option<Url>,

    /// URL of the resource's terms of service.
    pub resource_tos_uri: Option<Url>,
}

impl Oauth20ResourceMetadata {
    /// Builds the metadata's well-known URL for a resource, inserting
    /// the well-known path between host and resource path components
    /// (the same transformation rule as RFC 8414 §3.1).
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc9728#section-3.1>
    pub fn well_known_url(resource: &Url) -> Url {
        insert_well_known(resource, "/.well-known/oauth-protected-resource")
    }
}

/// Deserializes resource metadata from JSON bytes.
impl TryFrom<&[u8]> for Oauth20ResourceMetadata {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Extracts the `resource_metadata` parameter of a `WWW-Authenticate`
/// header value (parsed by io-http's rfc9110 challenge module): the
/// URL a protected resource points its 401s at, so a client discovers
/// the metadata without knowing the well-known rule.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc9728#section-5.1>
pub fn challenge_resource_metadata(value: &str) -> Option<Url> {
    parse_challenges(value)
        .iter()
        .find_map(|challenge| challenge.param("resource_metadata"))
        .and_then(|url| Url::parse(url).ok())
}

/// Errors that can occur during the coroutine progression.
#[derive(Debug, Error)]
pub enum Oauth20FetchResourceMetadataError {
    #[error(transparent)]
    SendHttpFetch(#[from] Http11SendError),
    #[error(transparent)]
    ParseHttpResponse(#[from] serde_json::Error),
    #[error("Unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
    #[error("Unexpected status {code} fetching resource metadata")]
    Status { code: u16 },
}

/// Result returned by the coroutine's resume function.
#[derive(Debug)]
pub enum Oauth20FetchResourceMetadataResult {
    /// The coroutine has successfully terminated its execution.
    Ok(Oauth20ResourceMetadata),
    /// The coroutine wants the socket to be read into.
    WantsRead,
    /// The coroutine wants the given bytes to be written to the
    /// socket.
    WantsWrite(Vec<u8>),
    /// The coroutine encountered an error.
    Err(Oauth20FetchResourceMetadataError),
}

/// The I/O-free coroutine to fetch protected resource metadata.
///
/// This coroutine sends a GET request to the metadata URL (from a
/// `WWW-Authenticate` challenge via [`challenge_resource_metadata`],
/// or built with [`Oauth20ResourceMetadata::well_known_url`]) and
/// receives the JSON metadata.
pub struct Oauth20FetchResourceMetadata {
    send: Http11Send,
}

impl Oauth20FetchResourceMetadata {
    /// Creates a new I/O-free coroutine to fetch resource metadata.
    pub fn new(request: HttpRequest) -> Self {
        let request = request.header("Accept", "application/json");

        Self {
            send: Http11Send::new(request),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> Oauth20FetchResourceMetadataResult {
        match self.send.resume(arg) {
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. }))
                if response.status.is_success() =>
            {
                match Oauth20ResourceMetadata::try_from(response.body.as_slice()) {
                    Ok(metadata) => Oauth20FetchResourceMetadataResult::Ok(metadata),
                    Err(err) => Oauth20FetchResourceMetadataResult::Err(err.into()),
                }
            }
            HttpCoroutineState::Complete(Ok(HttpSendOutput { response, .. })) => {
                Oauth20FetchResourceMetadataResult::Err(Oauth20FetchResourceMetadataError::Status {
                    code: *response.status,
                })
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRead) => {
                Oauth20FetchResourceMetadataResult::WantsRead
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsWrite(bytes)) => {
                Oauth20FetchResourceMetadataResult::WantsWrite(bytes)
            }
            HttpCoroutineState::Yielded(HttpSendYield::WantsRedirect { url, response, .. }) => {
                Oauth20FetchResourceMetadataResult::Err(
                    Oauth20FetchResourceMetadataError::Redirect {
                        url,
                        code: *response.status,
                    },
                )
            }
            HttpCoroutineState::Complete(Err(err)) => {
                Oauth20FetchResourceMetadataResult::Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::v2_0::rfc9728::resource_metadata::{
        Oauth20ResourceMetadata, challenge_resource_metadata,
    };

    #[test]
    fn well_known_url_inserts_the_resource_path() {
        let resource: Url = "https://api.example.com/jmap/session".parse().unwrap();
        assert_eq!(
            Oauth20ResourceMetadata::well_known_url(&resource).as_str(),
            "https://api.example.com/.well-known/oauth-protected-resource/jmap/session",
        );
    }

    #[test]
    fn challenge_yields_the_metadata_url() {
        // The fastmail shape: one Bearer challenge, quoted parameter.
        let challenge = r#"Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/jmap/session""#;
        let url = challenge_resource_metadata(challenge).unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.example.com/.well-known/oauth-protected-resource/jmap/session",
        );

        // Extra challenges and parameters ride along.
        let challenge = r#"Basic realm="dav", Bearer resource_metadata="https://example.com/meta", error="invalid_token""#;
        let url = challenge_resource_metadata(challenge).unwrap();
        assert_eq!(url.as_str(), "https://example.com/meta");

        assert!(challenge_resource_metadata("Bearer realm=\"x\"").is_none());
        assert!(challenge_resource_metadata("Bearer resource_metadata=").is_none());
    }
}
