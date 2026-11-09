---
cairn: change
id: independent-random-draws
status: landed
created: 2026-11-09
---

# Draw state and PKCE characters independently

## Why

`Oauth20PkceCodeVerifier` and `Oauth20State` draw their characters with rand's `IndexedRandom::sample` (`new`) and `sample_array` (`Default`), which choose distinct elements without repetition (rand 0.10 src/seq/slice.rs). Two consequences:

- No character ever repeats, which lowers the entropy: a 43-character verifier carries about 234 bits instead of about 260 with independent draws over the 66 unreserved characters, and a 32-character state about 202 bits instead of about 210 over the 95 VSCHAR ones.
- `sample` returns at most the alphabet's length, so `Oauth20PkceCodeVerifier::new(128)` yields 66 characters although its doc promises a size clamped to 43-128, and `Oauth20State::new(size)` stops at 95 characters.

No other part of the crate uses rand.

## What

- Replace rand with getrandom 0.4 used directly (no default features, none needed); the `client` feature becomes `["dep:getrandom"]`.
- One private helper at the crate root (src/random.rs) draws each character independently and uniformly from its alphabet: it fills the buffer with OS random bytes, keeps a byte `b` only when `b < 256 - 256 % len` (rejection sampling, no modulo bias), maps it to `alphabet[b % len]`, and refills the missing tail until the wanted length is reached.
- `new` on both types calls the helper; the `Default` impls call `new` with the unchanged default sizes (43 and 32).
- A failing OS random source panics with a clear message, as `rand::rng()` did, since `Default` cannot return an error; the docs say so.
- The public API is unchanged: `new(size: u8)`, `Default`, the verifier's 43 to 128 clamp.

Tests, written first and failing on the rand code: a 128-byte verifier holds 128 unreserved bytes, verifier sizes clamp to 43 and 128, a 255-byte state holds 255 VSCHAR bytes, and the default lengths stay 43 and 32. A length above the alphabet size proves repetition by pigeonhole, so no statistical test is needed.
