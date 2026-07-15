//! OAuth 2.0 Device Authorization Grant (RFC 8628).
//!
//! The user-code flow for hosts without a browser: request a device
//! and user code pair, then poll the token endpoint until the end
//! user completes the authorization on another device.

pub mod auth;
pub mod token;
