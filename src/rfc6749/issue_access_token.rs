//! Access token issuance (RFC 6749 section 5).
//!
//! The token endpoint response shared by every grant: the issued
//! token params on success, the error params otherwise. Consumed by
//! the access token request, refresh, client credentials and device
//! grant coroutines.

use alloc::string::String;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};

/// The access token response: success params, or error params.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-5>
pub type Oauth20AccessTokenResponse =
    Result<Oauth20AccessTokenSuccessParams, Oauth20AccessTokenErrorParams>;

/// The successful access token response.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.1>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Oauth20AccessTokenSuccessParams {
    /// The issued access token.
    #[serde(serialize_with = "serialize_secret_string")]
    pub access_token: SecretString,
    /// The type of the token issued (usually `Bearer`).
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-7.1>
    pub token_type: String,
    /// The lifetime of the access token, in seconds.
    pub expires_in: Option<usize>,
    /// The refresh token, to obtain new access tokens from the same grant.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-6>
    #[serde(serialize_with = "serialize_opt_secret_string")]
    pub refresh_token: Option<SecretString>,
    /// The granted scope, when it differs from the requested one.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub scope: Option<String>,
    /// Unix epoch seconds when the token was issued.
    ///
    /// Outside the OAuth specs; populated from the HTTP `Date` header, `None`
    /// when the server sent none. Callers compute expiry as `issued_at +
    /// expires_in` against their own clock.
    #[serde(default)]
    pub issued_at: Option<u64>,
}

/// Parses an HTTP IMF-fixdate into Unix epoch seconds (UTC).
///
/// Format: `Sun, 06 Nov 1994 08:49:37 GMT` (29 ASCII bytes); returns `None` on
/// any structural deviation. Does not check that the day-of-month is legal for
/// the month/year, relying on origin servers to send well-formed dates.
pub fn parse_http_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();

    if b.len() != 29 || &b[26..29] != b"GMT" {
        return None;
    }

    let day = parse_2_digits(&b[5..7])? as u64;
    let month: u64 = match &b[8..11] {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return None,
    };
    let year = parse_4_digits(&b[12..16])? as u64;
    let hour = parse_2_digits(&b[17..19])? as u64;
    let min = parse_2_digits(&b[20..22])? as u64;
    let sec = parse_2_digits(&b[23..25])? as u64;

    // NOTE: Howard Hinnant's days_from_civil algorithm; treats March as the
    // first month so the leap day lands at the end of the year.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_from_epoch = era * 146097 + doe - 719468;

    Some(days_from_epoch * 86400 + hour * 3600 + min * 60 + sec)
}

fn parse_2_digits(b: &[u8]) -> Option<u32> {
    let a = (b[0] as u32).wrapping_sub(b'0' as u32);
    let c = (b[1] as u32).wrapping_sub(b'0' as u32);
    if a > 9 || c > 9 {
        return None;
    }
    Some(a * 10 + c)
}

fn parse_4_digits(b: &[u8]) -> Option<u32> {
    Some(parse_2_digits(&b[0..2])? * 100 + parse_2_digits(&b[2..4])?)
}

/// Serializes success params into JSON string.
// SAFETY: exposes access and refresh tokens
impl TryFrom<&Oauth20AccessTokenSuccessParams> for String {
    type Error = serde_json::Error;

    fn try_from(params: &Oauth20AccessTokenSuccessParams) -> Result<Self, Self::Error> {
        serde_json::to_string(params)
    }
}

/// Deserializes success params from JSON bytes.
impl TryFrom<&[u8]> for Oauth20AccessTokenSuccessParams {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The error access token response.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
#[derive(Clone, Debug, Deserialize)]
pub struct Oauth20AccessTokenErrorParams {
    /// A single ASCII error code.
    pub error: Oauth20AccessTokenErrorCode,
    /// Human-readable text explaining the error.
    pub error_description: Option<String>,
    /// A URI to a human-readable page about the error.
    pub error_uri: Option<String>,
}

/// Parses error params from JSON bytes.
impl TryFrom<&[u8]> for Oauth20AccessTokenErrorParams {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The error code of the [`Oauth20AccessTokenErrorParams`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oauth20AccessTokenErrorCode {
    /// Client authentication failed.
    InvalidClient,
    /// The grant or refresh token is invalid, expired, or revoked.
    InvalidGrant,
    /// The request is malformed or missing a required parameter.
    InvalidRequest,
    /// The requested scope is invalid or exceeds the granted scope.
    InvalidScope,
    /// The client is not authorized to use this grant type.
    UnauthorizedClient,
    /// The server does not support this grant type.
    UnsupportedGrantType,
    /// The device flow is pending; keep polling at the current interval.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.5>
    AuthorizationPending,
    /// The device flow is pending; increase the polling interval by 5s.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.5>
    SlowDown,
    /// The authorization request was denied.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.5>
    AccessDenied,
    /// The device code has expired; the session is over.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8628#section-3.5>
    ExpiredToken,
    /// The end user denied the request.
    ///
    /// Non-standard Microsoft Entra code, in place of `access_denied`.
    AuthorizationDeclined,
    /// The device code was not recognized.
    ///
    /// Non-standard Microsoft Entra code.
    BadVerificationCode,
    /// The `resource` parameter is invalid or missing (RFC 8707).
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8707#section-3>
    InvalidTarget,
    /// Any unregistered code, kept for provider-specific extensions.
    #[serde(other)]
    Unknown,
}

fn serialize_secret_string<S: Serializer>(secret: &SecretString, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(secret.expose_secret())
}

fn serialize_opt_secret_string<S: Serializer>(
    secret: &Option<SecretString>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(secret) => serialize_secret_string(secret, s),
        None => s.serialize_none(),
    }
}
