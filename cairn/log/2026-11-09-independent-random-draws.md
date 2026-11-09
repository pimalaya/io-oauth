---
cairn: log
change: independent-random-draws
landed: 2026-11-09
---

# Draw state and PKCE characters independently

`Oauth20State` and `Oauth20PkceCodeVerifier` drew their characters with rand's `IndexedRandom::sample` and `sample_array`, which pick distinct elements: no character ever repeated (a 43-character verifier carried about 234 bits instead of about 260, a 32-character state about 202 instead of about 210), and `sample` capped the output at the alphabet's length, so `Oauth20PkceCodeVerifier::new(128)` held 66 characters and `Oauth20State::new` stopped at 95. No other code used rand.

rand gave way to getrandom 0.4 (no default features, none needed; the `client` feature is now `["dep:getrandom"]`). The private crate-root helper `random_chars` in src/random.rs fills the output with `getrandom::fill`, keeps a byte `b` only when `b < 256 - 256 % len` (rejection sampling, no modulo bias; limits 198 for the 66 unreserved characters, 190 for the 95 VSCHAR ones), maps it to `alphabet[b % len]` in place, and refills the missing tail until the size is reached. Both `new` call it, both `Default` impls call `new` (43 and 32, unchanged). A failing OS random source panics with "cannot read the OS random source", as `rand::rng()` did, and the docs say so. The public API is unchanged. The client tree (`cargo tree -e normal --no-default-features --features client`) went from 63 to 60 crates: rand, rand_core and chacha20 left.

Capabilities moved: `authorization-code-grant` (CSRF state and PKCE modified, Random characters added), `packaging` (Source layout modified).

Verified: `a_128_byte_verifier_holds_128_unreserved_bytes`, `verifier_sizes_clamp_to_43_and_128` and `a_255_byte_state_holds_255_vschar_bytes` failed on the rand code (66, 66 and 95 bytes) and pass now, along with `the_default_verifier_holds_43_unreserved_bytes` and `the_default_state_holds_32_vschar_bytes`; a length above the alphabet size proves repetition by pigeonhole. `cargo fmt --check`, `cargo clippy -D warnings` over `--all-features --all-targets`, `--no-default-features`, `--no-default-features --features client` and `--no-default-features --features rustls-ring,jwt-bearer` clean, `cargo build --no-default-features` (no_std) clean, `cargo test --all-features` passed (26), `cargo deny check` ok.
