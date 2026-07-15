//! OAuth 2.0 Dynamic Client Registration (RFC 7591).
//!
//! Registers a client against an authorization server without any
//! provider console, and declares the preference order between the
//! ways a client obtains its registration.

pub mod register;
pub mod source;
