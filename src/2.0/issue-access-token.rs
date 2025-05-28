use secrecy::SecretString;
use serde::Deserialize;

pub type AccessTokenResponse = Result<AccessTokenSuccessfulResponse, AccessTokenErrorResponse>;

/// The response returned by the authorization server when the access
/// token request is valid and authorized.
///
/// The authorization server issues an access token and optional
/// refresh token, and constructs the response by adding the following
/// parameters to the entity-body of the HTTP response with a 200 (OK)
/// status code.
///
/// Refs: https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
///
#[derive(Clone, Debug, Deserialize)]
pub struct AccessTokenSuccessfulResponse {
    /// The access token issued by the authorization server.
    pub access_token: SecretString,

    /// The type of the token issued as described in [Section 7.1].
    ///
    /// [Section 7.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-7.1
    pub token_type: String,

    /// The lifetime in seconds of the access token.
    ///
    /// For example, the value "3600" denotes that the access token
    /// will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide
    /// the expiration time via other means or document the default
    /// value.
    pub expires_in: usize,

    /// The refresh token, which can be used to obtain new access
    /// tokens using the same authorization grant as described in
    /// [Section 6].
    ///
    /// [Section 6]: https://datatracker.ietf.org/doc/html/rfc6749#section-6
    pub refresh_token: Option<SecretString>,
}

impl TryFrom<&[u8]> for AccessTokenSuccessfulResponse {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The response returned by the authorization server when the access
/// token request is not valid or unauthorized.
///
/// The authorization server responds with an HTTP 400 (Bad Request)
/// status code (unless specified otherwise) and includes the
/// following parameters with the response.
///
/// Refs: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
///
#[derive(Clone, Debug, Deserialize)]
pub struct AccessTokenErrorResponse {
    #[serde(rename = "error")]
    pub code: AccessTokenErrorResponseCode,
    #[serde(rename = "error_description")]
    pub description: Option<String>,
    #[serde(rename = "error_uri")]
    pub uri: Option<String>,
}

/// The error code of the [`AccessTokenErrorResponse`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenErrorResponseCode {
    /// Client authentication failed (e.g., unknown client, no client
    /// authentication included, or unsupported authentication
    /// method).  The authorization server MAY return an HTTP 401
    /// (Unauthorized) status code to indicate which HTTP
    /// authentication schemes are supported.  If the client attempted
    /// to authenticate via the "Authorization" request header field,
    /// the authorization server MUST respond with an HTTP 401
    /// (Unauthorized) status code and include the "WWW-Authenticate"
    /// response header field matching the authentication scheme used
    /// by the client.
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code,
    /// resource owner credentials) or refresh token is invalid,
    /// expired, revoked, does not match the redirection URI used in
    /// the authorization request, or was issued to another client.
    InvalidGrant,

    /// The request is missing a required parameter, includes an
    /// unsupported parameter value (other than grant type), repeats a
    /// parameter, includes multiple credentials, utilizes more than
    /// one mechanism for authenticating the client, or is otherwise
    /// malformed.
    ///
    InvalidRequest,

    /// The requested scope is invalid, unknown, malformed, or exceeds
    /// the scope granted by the resource owner.
    InvalidScope,

    /// The authenticated client is not authorized to use this
    /// authorization grant type.
    UnauthorizedClient,

    /// The authorization grant type is not supported by the
    /// authorization server.
    UnsupportedGrantType,
}

impl TryFrom<&[u8]> for AccessTokenErrorResponse {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}
