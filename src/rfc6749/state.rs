//! Opaque state value used for CSRF protection (RFC 6749 section
//! 10.12).
//!
//! Sent on the authorization request and echoed back on the callback,
//! binding the two legs of the authorization code grant together.

use core::fmt;

use alloc::{string::String, vec::Vec};

use base64_codec::codec::{Base64Alphabet, Base64Codec};
use secrecy::{ExposeSecret, SecretBox};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error, Visitor},
};
use thiserror::Error as ThisError;

#[cfg(feature = "client")]
use crate::{random::random_chars, rfc7636::pkce::UNRESERVED};

// NOTE: VSCHAR = %x20-7E
const VSCHAR: [u8; 95] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
];

/// The value used to prevent CSRF attacks.
///
/// Represents an opaque value used by the client to maintain state
/// between the request and callback.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1>,
///       <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
#[derive(Clone, Debug)]
pub struct Oauth20State(SecretBox<[u8]>);

impl Oauth20State {
    /// Generates a random state of `size` unreserved bytes.
    ///
    /// Panics when the OS random source fails.
    #[cfg(feature = "client")]
    pub fn new(size: u8) -> Self {
        let random = random_chars(&UNRESERVED, size as usize);
        Self(SecretBox::from(random))
    }

    /// Builds a state out of 32 random bytes the caller drew.
    ///
    /// The bytes are base64url-encoded into 43 characters.
    pub fn from_entropy(entropy: &[u8; 32]) -> Self {
        let codec = Base64Codec {
            alphabet: Base64Alphabet::Url,
            pad: false,
            ..Base64Codec::default()
        };

        let mut state = Vec::new();
        codec.encode_vec(entropy, &mut state);

        Self(SecretBox::from(state))
    }

    /// Exposes the random state bytes.
    // SAFETY: this function exposes the random state
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl Eq for Oauth20State {}

impl PartialEq for Oauth20State {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

#[cfg(feature = "client")]
impl Default for Oauth20State {
    /// Generates a random state of 32 unreserved bytes.
    ///
    /// Panics when the OS random source fails.
    fn default() -> Self {
        Self::new(32)
    }
}

impl TryFrom<&[u8]> for Oauth20State {
    type Error = Oauth20StateError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // NOTE: state = 1*VSCHAR
        if bytes.is_empty() {
            return Err(Oauth20StateError::Empty);
        }

        for b in bytes {
            if !VSCHAR.contains(b) {
                return Err(Oauth20StateError::InvalidByte(*b));
            }
        }

        Ok(Self(SecretBox::from(bytes.to_vec())))
    }
}

/// Errors returned when building a state out of bytes.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
pub enum Oauth20StateError {
    /// The state holds no byte.
    #[error("Invalid empty state")]
    Empty,
    /// The state holds a byte outside the VSCHAR set.
    #[error("Invalid state byte 0x{0:x}")]
    InvalidByte(u8),
}

impl Serialize for Oauth20State {
    // SAFETY: exposes the random state
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let state = String::from_utf8_lossy(self.expose());
        serializer.serialize_str(&state)
    }
}

impl<'de> Deserialize<'de> for Oauth20State {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StateVisitor)
    }
}

struct StateVisitor;

impl<'de> Visitor<'de> for StateVisitor {
    type Value = Oauth20State;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string or bytes")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_bytes(value.as_bytes())
    }

    fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        Oauth20State::try_from(bytes).map_err(E::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde::de::value::{Error, StrDeserializer};

    use crate::rfc6749::state::*;

    /// Longer than the 66-character alphabet, so characters repeat.
    #[cfg(feature = "client")]
    #[test]
    fn a_255_byte_state_holds_255_unreserved_bytes() {
        let state = Oauth20State::new(255);

        assert_eq!(state.expose().len(), 255);
        assert!(state.expose().iter().all(|b| UNRESERVED.contains(b)));
    }

    #[cfg(feature = "client")]
    #[test]
    fn the_default_state_holds_32_unreserved_bytes() {
        let state = Oauth20State::default();

        assert_eq!(state.expose().len(), 32);
        assert!(state.expose().iter().all(|b| UNRESERVED.contains(b)));
    }

    #[test]
    fn an_empty_state_does_not_deserialize() {
        let state = Oauth20State::deserialize(StrDeserializer::<Error>::new(""));
        assert!(state.is_err());
    }

    #[test]
    fn a_state_is_one_or_more_vschar_bytes() {
        assert_eq!(
            Oauth20State::try_from(&b""[..]),
            Err(Oauth20StateError::Empty)
        );
        assert_eq!(
            Oauth20State::try_from(&b"a\nb"[..]),
            Err(Oauth20StateError::InvalidByte(b'\n'))
        );
        assert_eq!(
            Oauth20State::try_from(&b"a b"[..]).unwrap().expose(),
            b"a b"
        );
    }

    #[test]
    fn entropy_becomes_43_base64url_bytes() {
        let state = Oauth20State::from_entropy(&[0xFB; 32]);
        assert_eq!(
            state.expose(),
            "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s".as_bytes()
        );
    }
}
