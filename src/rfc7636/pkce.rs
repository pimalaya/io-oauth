//! Proof key for code exchange (RFC 7636).
//!
//! The code verifier and derived code challenge hardening the
//! authorization code grant for public clients: the challenge rides
//! on the authorization request, the verifier on the token exchange.

use core::str::FromStr;

use alloc::{borrow::Cow, string::String};
#[cfg(feature = "client")]
use alloc::{boxed::Box, vec::Vec};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use log::debug;
#[cfg(feature = "client")]
use rand::seq::IndexedRandom;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};

/// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// ALPHA = %x41-5A / %x61-7A
/// DIGIT = %x30-39
const UNRESERVED: [u8; 66] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, b'-', b'.',
    b'_', b'~',
];

/// The PKCE code challenge sent on the authorization request.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7636#section-4.2>
#[cfg_attr(feature = "client", derive(Default))]
#[derive(Clone, Debug)]
pub struct Oauth20PkceCodeChallenge {
    /// The transformation applied to the verifier.
    pub method: Oauth20PkceCodeChallengeMethod,
    /// The code verifier the challenge is derived from.
    pub verifier: Oauth20PkceCodeVerifier,
}

impl Oauth20PkceCodeChallenge {
    /// Returns the challenge encoded per its method (base64url for `S256`).
    pub fn encode(&self) -> Cow<'_, str> {
        match self.method {
            Oauth20PkceCodeChallengeMethod::Plain => {
                let verifier = self.verifier.expose();
                String::from_utf8_lossy(verifier)
            }
            Oauth20PkceCodeChallengeMethod::Sha256 => {
                let digest = Sha256::digest(self.verifier.expose());
                BASE64_URL_SAFE_NO_PAD.encode(digest).into()
            }
        }
    }
}

/// The transformation from code verifier to code challenge.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7636#section-4.2>
#[derive(Clone, Debug, Default)]
pub enum Oauth20PkceCodeChallengeMethod {
    /// The challenge is the verifier verbatim.
    Plain,
    /// The challenge is the base64url-encoded SHA-256 of the verifier.
    #[default]
    Sha256,
}

impl Oauth20PkceCodeChallengeMethod {
    const PLAIN: &'static str = "plain";
    const SHA256: &'static str = "S256";

    /// Returns the method's wire value (`plain` or `S256`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => Self::PLAIN,
            Self::Sha256 => Self::SHA256,
        }
    }
}

/// The high-entropy secret the code challenge is derived from.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc7636#section-4.1>
#[derive(Clone, Debug)]
pub struct Oauth20PkceCodeVerifier(SecretBox<[u8]>);

impl Oauth20PkceCodeVerifier {
    /// Generates a random verifier of `size` unreserved bytes (clamped 43-128).
    #[cfg(feature = "client")]
    pub fn new(size: u8) -> Self {
        // NOTE: code-verifier = 43*128unreserved
        let size = size.clamp(43, 128) as usize;

        let random: Vec<u8> = UNRESERVED.sample(&mut rand::rng(), size).cloned().collect();

        Self(SecretBox::from(random))
    }

    /// Exposes the code verifier.
    // SAFETY: this function exposes the code verifier
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

#[cfg(feature = "client")]
impl Default for Oauth20PkceCodeVerifier {
    fn default() -> Self {
        // NOTE: code-verifier = 43*128unreserved
        let random: [u8; 43] = UNRESERVED
            .sample_array(&mut rand::rng())
            // SAFETY: unreserved is not empty
            .unwrap();

        Self(SecretBox::new(Box::new(random)))
    }
}

impl FromStr for Oauth20PkceCodeVerifier {
    type Err = u8;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();

        for b in bytes {
            if !UNRESERVED.contains(b) {
                debug!("invalid byte 0x{b:x} found in PKCE code challenge");
                return Err(*b);
            }
        }

        Ok(Self(SecretBox::from(bytes.to_vec())))
    }
}
