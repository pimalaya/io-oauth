---
cairn: tasks
change: independent-random-draws
---

# Tasks

- [x] Tests on the rand code, confirmed failing: 128-byte verifier, verifier clamp, 255-byte state; default lengths guarded
- [x] src/random.rs: rejection-sampling helper over `getrandom::fill`
- [x] `Oauth20PkceCodeVerifier` and `Oauth20State` on the helper, `Default` over `new`, panic documented
- [x] Cargo.toml: rand replaced by getrandom 0.4, `client = ["dep:getrandom"]`
- [x] fmt, clippy over the feature matrix, tests, cargo deny
- [x] CHANGELOG; fold into cairn/spec/authorization-code-grant.md and cairn/spec/packaging.md; log; archive
