---
cairn: log
change: the-layered-features
landed: 2026-11-21
---

# The layered features

The crate moves to the family's layered feature shape (GUIDELINES cargo-006), the one io-imap, io-smtp and io-webdav ship. The old `client` feature, which gated the std-blocking client and std, is renamed `std`. `client` now gates the coroutines (`rfc6749::access_token_request`, `rfc6749::client_credentials`, `rfc6749::refresh_access_token`, `rfc7009`, `rfc7523::auth_grant`, `rfc7523::client_auth`, `rfc7591::register`, `rfc8628`) and the random state and code verifier generators, and makes io-http optional beside getrandom; it is on by default and implied by `std` and the TLS features, which now imply `std`. `vendored` forwards weakly to io-http too. The vocabulary (authorization request and response, issued token, state and verifier from caller bytes, PKCE, registration source, assertion claims) stays compiled under no feature.

No change folder: the shape is the family rule, applied as io-webdav applied it on 2026-11-18.

The io-http requirement stays 0.8, whose coroutines are ungated, so no io-http feature is named for `client`. The io-http release moving to the same shape gates its coroutines behind its own `client`: the bump to it adds `io-http/client` to this crate's `client` feature.

Capabilities moved: packaging ("no_std core", "Feature layering" modified), client (feature name modified), jwt-bearer ("Signing is feature-gated" modified).

Verified: `cargo build` with no features, `client`, `std`, `jwt-bearer` alone, default and all features; `cargo test` with no features (20 unit), `std` (66 unit, 9 doc) and all features (73 unit, 10 doc); `cargo clippy --all-features --all-targets` and `cargo fmt --check` clean.
