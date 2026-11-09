//! Random characters drawn from an alphabet.
//!
//! Generates the CSRF state and the PKCE code verifier out of the OS
//! random source.

use alloc::{vec, vec::Vec};

use getrandom::fill;

/// Draws `size` characters independently and uniformly from `alphabet`.
///
/// `alphabet` holds 1 to 256 characters. Panics when the OS random
/// source fails.
pub(crate) fn random_chars(alphabet: &[u8], size: usize) -> Vec<u8> {
    let len = alphabet.len();
    // NOTE: bytes from `limit` up would favour the first characters
    let limit = 256 - 256 % len;

    let mut chars = vec![0; size];
    let mut filled = 0;

    while filled < size {
        fill(&mut chars[filled..]).expect("cannot read the OS random source");

        let mut kept = filled;

        for i in filled..size {
            let byte = chars[i] as usize;

            if byte < limit {
                chars[kept] = alphabet[byte % len];
                kept += 1;
            }
        }

        filled = kept;
    }

    chars
}
