//! JWT bearer assertion format and signing (RFC 7523 section 3).
//!
//! The claim set carried by a JWT bearer assertion, and the RS256
//! signing key producing the compact JWS consumed by the auth grant
//! and client auth sibling modules. Everything here is I/O-free and
//! clock-free: the time claims (`iat`, `exp`, `nbf`) and the `jti`
//! identifier are caller-provided, never read from a clock. The
//! claims are plain serde wire shapes and stay unconditional, while
//! the signing key and the x5t helper sit behind the `jwt-bearer`
//! feature since they pull the rsa and sha1 crates.

use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::String,
};

#[cfg(feature = "jwt-bearer")]
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
#[cfg(feature = "jwt-bearer")]
use log::{debug, trace};
#[cfg(feature = "jwt-bearer")]
use rsa::{
    RsaPrivateKey,
    pkcs1::{self, DecodeRsaPrivateKey},
    pkcs1v15::SigningKey,
    pkcs8::{self, DecodePrivateKey},
    signature::{SignatureEncoding, Signer},
};
#[cfg(feature = "jwt-bearer")]
use secrecy::SecretString;
use serde::{Serialize, Serializer};
use serde_json::Value;
#[cfg(feature = "jwt-bearer")]
use sha1::Sha1;
#[cfg(feature = "jwt-bearer")]
use sha2::{Digest, Sha256};
#[cfg(feature = "jwt-bearer")]
use thiserror::Error;

/// The claim set of a JWT bearer assertion.
///
/// Serializes to the JWT payload JSON. `iss` and `aud` are always
/// required; `exp` is required by the spec too, but stays optional
/// here so a std layer can default it from a clock, and
/// [`Oauth20JwtBearerKey::sign`] rejects a claim set leaving it
/// unset. The audience is usually the token endpoint URL the
/// assertion is sent to.
///
/// For the Google service account flow, `iss` is the service account
/// email, `sub` the impersonated user for domain-wide delegation, and
/// the requested scopes ride in the `scope` claim rather than in the
/// request body. For Microsoft certificate credentials, `iss` and
/// `sub` are both the application (client) id.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7523#section-3>
#[derive(Clone, Debug, Default, Serialize)]
pub struct Oauth20JwtBearerClaims<'a> {
    /// The issuer of the assertion, identifying the client.
    pub iss: Cow<'a, str>,
    /// The subject the assertion is about.
    ///
    /// The client itself for client authentication, or the user to
    /// impersonate for an authorization grant with delegation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<Cow<'a, str>>,
    /// The audience of the assertion, usually the token endpoint URL.
    pub aud: Cow<'a, str>,
    /// Unix epoch seconds when the assertion expires.
    ///
    /// Required by the spec; caller-provided since the coroutine
    /// layer reads no clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Unix epoch seconds when the assertion was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Unix epoch seconds before which the assertion is not valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// The unique identifier of the assertion, for replay protection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<Cow<'a, str>>,
    /// The scope of the access request, as a claim.
    ///
    /// Serialized space-delimited. Google reads the requested scopes
    /// from this claim on the authorization grant.
    #[serde(
        skip_serializing_if = "BTreeSet::is_empty",
        serialize_with = "serialize_scope"
    )]
    pub scope: BTreeSet<Cow<'a, str>>,
    /// Extra provider-specific claims, flattened into the payload.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn serialize_scope<S: Serializer>(scope: &BTreeSet<Cow<'_, str>>, s: S) -> Result<S::Ok, S::Error> {
    let mut joined = String::new();
    let mut glue = "";

    for token in scope {
        joined.push_str(glue);
        joined.push_str(token);
        glue = " ";
    }

    s.serialize_str(&joined)
}

/// The JOSE header of a JWT bearer assertion, kept internal so the
/// advertised algorithm always matches the RS256 signature produced.
#[cfg(feature = "jwt-bearer")]
#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5t: Option<&'a str>,
}

/// Errors that can occur while parsing a signing key.
#[cfg(feature = "jwt-bearer")]
#[derive(Debug, Error)]
pub enum Oauth20JwtBearerKeyError {
    /// The PKCS#8 private key could not be parsed.
    #[error("Parse PKCS#8 RSA private key: {0}")]
    Pkcs8(#[from] pkcs8::Error),
    /// The PKCS#1 private key could not be parsed.
    #[error("Parse PKCS#1 RSA private key: {0}")]
    Pkcs1(#[from] pkcs1::Error),
}

/// Errors that can occur while signing an assertion.
#[cfg(feature = "jwt-bearer")]
#[derive(Debug, Error)]
pub enum Oauth20JwtBearerSignError {
    /// The claim set leaves the required `exp` claim unset.
    #[error("Missing exp claim in JWT bearer assertion")]
    MissingExpClaim,
    /// The header or claims could not be serialized to JSON.
    #[error("Serialize JWT bearer assertion: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The RS256 signature could not be produced.
    #[error("Sign JWT bearer assertion: {0}")]
    Sign(#[from] rsa::signature::Error),
}

/// The RSA private key signing JWT bearer assertions with RS256.
///
/// Parsed from PKCS#8 or PKCS#1, PEM or DER. RS256 (RSASSA-PKCS1-v1_5
/// with SHA-256) is the algorithm every RFC 7523 provider accepts,
/// Microsoft and Google included.
///
/// # Example
///
/// ```rust,no_run
/// use io_oauth::rfc7523::assertion::*;
///
/// let key = Oauth20JwtBearerKey::from_pkcs8_pem("-----BEGIN PRIVATE KEY-----…").unwrap();
///
/// let claims = Oauth20JwtBearerClaims {
///     iss: "service-account@example.iam.gserviceaccount.com".into(),
///     sub: Some("impersonated-user@example.com".into()),
///     aud: "https://oauth2.googleapis.com/token".into(),
///     iat: Some(1_720_000_000),
///     exp: Some(1_720_000_600),
///     scope: ["https://mail.google.com/".into()].into(),
///     ..Default::default()
/// };
///
/// let assertion = key.sign(&claims, None).unwrap();
/// ```
#[cfg(feature = "jwt-bearer")]
pub struct Oauth20JwtBearerKey {
    key: SigningKey<Sha256>,
}

#[cfg(feature = "jwt-bearer")]
impl Oauth20JwtBearerKey {
    /// Parses a signing key from a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Oauth20JwtBearerKeyError> {
        Ok(Self {
            key: SigningKey::new(RsaPrivateKey::from_pkcs8_pem(pem)?),
        })
    }

    /// Parses a signing key from PKCS#8 DER bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Oauth20JwtBearerKeyError> {
        Ok(Self {
            key: SigningKey::new(RsaPrivateKey::from_pkcs8_der(der)?),
        })
    }

    /// Parses a signing key from a PKCS#1 PEM document
    /// (`-----BEGIN RSA PRIVATE KEY-----`).
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, Oauth20JwtBearerKeyError> {
        Ok(Self {
            key: SigningKey::new(RsaPrivateKey::from_pkcs1_pem(pem)?),
        })
    }

    /// Parses a signing key from PKCS#1 DER bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Oauth20JwtBearerKeyError> {
        Ok(Self {
            key: SigningKey::new(RsaPrivateKey::from_pkcs1_der(der)?),
        })
    }

    /// Signs the claims into a compact JWS assertion.
    ///
    /// Assembles `base64url(header).base64url(claims)` with the
    /// header `{"alg":"RS256","typ":"JWT"}`, signs it with
    /// RSASSA-PKCS1-v1_5 SHA-256, and appends the base64url
    /// signature. The optional `x5t` is the base64url SHA-1
    /// thumbprint of the client certificate, required by Microsoft
    /// for certificate credentials (see [`x5t_from_der`]).
    pub fn sign(
        &self,
        claims: &Oauth20JwtBearerClaims<'_>,
        x5t: Option<&str>,
    ) -> Result<SecretString, Oauth20JwtBearerSignError> {
        debug!("begin JWT bearer assertion signing");

        if claims.exp.is_none() {
            return Err(Oauth20JwtBearerSignError::MissingExpClaim);
        }

        let header = serde_json::to_string(&Header {
            alg: "RS256",
            typ: "JWT",
            x5t,
        })?;
        let payload = serde_json::to_string(claims)?;
        trace!("header: {header}, payload: {payload}");

        let mut jws = BASE64_URL_SAFE_NO_PAD.encode(header);
        jws.push('.');
        jws.push_str(&BASE64_URL_SAFE_NO_PAD.encode(payload));

        let signature = self.key.try_sign(jws.as_bytes())?;
        jws.push('.');
        jws.push_str(&BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()));

        debug!("end of JWT bearer assertion signing");
        Ok(jws.into())
    }
}

#[cfg(feature = "jwt-bearer")]
impl core::fmt::Debug for Oauth20JwtBearerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Oauth20JwtBearerKey")
            .finish_non_exhaustive()
    }
}

/// Computes the `x5t` header value from DER certificate bytes: the
/// base64url-encoded SHA-1 thumbprint of the certificate.
///
/// Microsoft requires it on assertions signed with certificate
/// credentials. Without this helper, compute it as
/// `base64url(sha1(cert_der))` with no padding.
#[cfg(feature = "jwt-bearer")]
pub fn x5t_from_der(cert_der: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha1::digest(cert_der))
}

#[cfg(all(test, feature = "jwt-bearer"))]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use rsa::{
        RsaPrivateKey,
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::DecodePrivateKey,
        signature::Verifier,
    };
    use secrecy::ExposeSecret;
    use serde_json::{Value, json};
    use sha2::Sha256;

    use crate::rfc7523::assertion::*;

    /// Deterministic 2048-bit test key, the RustCrypto pkcs8 crate's
    /// rsa2048-priv.pem example.
    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2xCxRXxCmqvKC
xj7b4kJDoXDz+iYzvUgzY39Hyk9vNuA6XSnvwxkayA85DYdLOeMPQU/Owfyg7YHl
R+3CzTgsdvYckBiXPbn6U3lyp8cB9rd+CYLfwV/AGSfuXnzZS09Zn/BwE6fIKBvf
Ity8mtfKu3xDEcmC9Y7bchOtRVizMiZtdDrtgZLRiEytuLFHOaja2mbclwgG2ces
RQyxPQ18V1+xmFNPxhvEG8DwV04OATDHu7+9/cn2puLj4q/xy+rIm6V4hFKNVc+w
gyeh6MifTgA88oiOkzJB2daVvLus3JC0Tj4JX6NwWOolsT9eKVy+rG3oOKuMUK9h
4piXW4cvAgMBAAECggEAfsyDYsDtsHQRZCFeIvdKudkboGkAcAz2NpDlEU2O5r3P
uy4/lhRpKmd6CD8Wil5S5ZaOZAe52XxuDkBk+C2gt1ihTxe5t9QfX0jijWVRcE9W
5p56qfpjD8dkKMBtJeRV3PxVt6wrT3ZkP97T/hX/eKuyfmWsxKrQvfbbJ+9gppEM
XEoIXtQydasZwdmXoyxu/8598tGTX25gHu3hYaErXMJ8oh+B0smcPR6gjpDjBTqw
m++nJN7w0MOjwel0DA2fdhJqFJ7Aqn2AeCBUhCVNlR2wfEz5H7ZFTAlliP1ZJNur
6zWcogJSaNAE+dZus9b3rcETm61A8W3eY54RZHN2wQKBgQDcwGEkLU6Sr67nKsUT
ymW593A2+b1+Dm5hRhp+92VCJewVPH5cMaYVem5aE/9uF46HWMHLM9nWu+MXnvGJ
mOQi7Ny+149Oz9vl9PzYrsLJ0NyGRzypvRbZ0jjSH7Xd776xQ8ph0L1qqNkfM6CX
eQ6WQNvJEIXcXyY0O6MTj2stZwKBgQDT8xR1fkDpVINvkr4kI2ry8NoEo0ZTwYCv
Z+lgCG2T/eZcsj79nQk3R2L1mB42GEmvaM3XU5T/ak4G62myCeQijbLfpw5A9/l1
ClKBdmR7eI0OV3eiy4si480mf/cLTzsC06r7DhjFkKVksDGIsKpfxIFWsHYiIUJD
vRIn76fy+QKBgQDOaLesGw0QDWNuVUiHU8XAmEP9s5DicF33aJRXyb2Nl2XjCXhh
fi78gEj0wyQgbbhgh7ZU6Xuz1GTn7j+M2D/hBDb33xjpqWPE5kkR1n7eNAQvLibj
06GtNGra1rm39ncIywlOYt7p/01dZmmvmIryJV0c6O0xfGp9hpHaNU0S2wKBgCX2
5ZRCIChrTfu/QjXA7lhD0hmAkYlRINbKeyALgm0+znOOLgBJj6wKKmypacfww8oa
sLxAKXEyvnU4177fTLDvxrmO99ulT1aqmaq85TTEnCeUfUZ4xRxjx4x84WhyMbTI
61h65u8EgMuvT8AXPP1Yen5nr1FfubnedREYOXIpAoGAMZlUBtQGIHyt6uo1s40E
DF+Kmhrggn6e0GsVPYO2ghk1tLNqgr6dVseRtYwnJxpXk9U6HWV8CJl5YLFDPlFx
mH9FLxRKfHIwbWPh0//Atxt1qwjy5FpILpiEUcvkeOEusijQdFbJJLZvbO0EjYU/
Uz4xpoYU8cPObY7JmDznKvc=
-----END PRIVATE KEY-----
";

    fn verifying_key() -> VerifyingKey<Sha256> {
        let key = RsaPrivateKey::from_pkcs8_pem(KEY_PEM).unwrap();
        VerifyingKey::new(key.to_public_key())
    }

    fn google_claims() -> Oauth20JwtBearerClaims<'static> {
        Oauth20JwtBearerClaims {
            iss: "sa@project.iam.gserviceaccount.com".into(),
            sub: Some("user@example.com".into()),
            aud: "https://oauth2.googleapis.com/token".into(),
            exp: Some(1_720_000_600),
            iat: Some(1_720_000_000),
            jti: Some("id-1".into()),
            scope: ["https://mail.google.com/".into()].into(),
            ..Default::default()
        }
    }

    fn split(jws: &str) -> (String, String, Vec<u8>) {
        let mut parts = jws.split('.');
        let header = parts.next().unwrap();
        let payload = parts.next().unwrap();
        let signature = parts.next().unwrap();
        assert_eq!(parts.next(), None);

        (
            String::from(header),
            String::from(payload),
            BASE64_URL_SAFE_NO_PAD.decode(signature).unwrap(),
        )
    }

    #[test]
    fn assertion_signs_header_claims_and_verifiable_signature() {
        let key = Oauth20JwtBearerKey::from_pkcs8_pem(KEY_PEM).unwrap();
        let jws = key.sign(&google_claims(), Some("thumb")).unwrap();
        let (header, payload, signature) = split(jws.expose_secret());

        let decoded: Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&header).unwrap()).unwrap();
        assert_eq!(
            decoded,
            json!({"alg": "RS256", "typ": "JWT", "x5t": "thumb"})
        );

        let decoded: Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&payload).unwrap()).unwrap();
        assert_eq!(
            decoded,
            json!({
                "iss": "sa@project.iam.gserviceaccount.com",
                "sub": "user@example.com",
                "aud": "https://oauth2.googleapis.com/token",
                "exp": 1_720_000_600,
                "iat": 1_720_000_000,
                "jti": "id-1",
                "scope": "https://mail.google.com/",
            })
        );

        let signature = Signature::try_from(signature.as_slice()).unwrap();
        let signing_input = format!("{header}.{payload}");
        verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn assertion_without_x5t_omits_the_header_param() {
        let key = Oauth20JwtBearerKey::from_pkcs8_pem(KEY_PEM).unwrap();
        let jws = key.sign(&google_claims(), None).unwrap();
        let (header, _, _) = split(jws.expose_secret());

        let decoded: Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&header).unwrap()).unwrap();
        assert_eq!(decoded, json!({"alg": "RS256", "typ": "JWT"}));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = Oauth20JwtBearerKey::from_pkcs8_pem(KEY_PEM).unwrap();
        let jws = key.sign(&google_claims(), None).unwrap();
        let (header, _, signature) = split(jws.expose_secret());

        let mut tampered = google_claims();
        tampered.sub = Some("attacker@example.com".into());
        let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&tampered).unwrap());

        let signature = Signature::try_from(signature.as_slice()).unwrap();
        let signing_input = format!("{header}.{payload}");
        assert!(
            verifying_key()
                .verify(signing_input.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn missing_exp_claim_is_rejected() {
        let key = Oauth20JwtBearerKey::from_pkcs8_pem(KEY_PEM).unwrap();
        let mut claims = google_claims();
        claims.exp = None;

        assert!(matches!(
            key.sign(&claims, None),
            Err(Oauth20JwtBearerSignError::MissingExpClaim)
        ));
    }

    #[test]
    fn x5t_thumbprint_matches_known_digest() {
        assert_eq!(
            x5t_from_der(b"example-cert-der"),
            "G8982Odi4bIpR3fqlbW9jOaBYa0"
        );
    }
}
