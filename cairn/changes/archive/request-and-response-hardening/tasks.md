---
cairn: tasks
change: request-and-response-hardening
---

# Tasks

- [x] Tests, confirmed failing before each fix: Basic credentials form-encoded, `Display` absent from the six params, coroutine `Debug` hiding the body, status without an OAuth body in the eight coroutines, string `expires_in`, missing `token_type`, verifier shorter than 43 and longer than 128, empty state, generated state unreserved, another issuer refused, forged and missing state skipped by the listener
- [x] `build_post_request`: id and secret form-urlencoded, unreserved characters literal (`~` included, with its test); double authentication documented
- [x] `iss` on the success params, `validate` with an expected issuer, `IssuerMismatch`
- [x] `await_redirect` and `await_redirect_on` with an expected state
- [x] `to_body` on six params, `Display` removed, hand-written `Debug` on `Oauth20AccessTokenRequest`
- [x] `Status(u16)` on eight errors
- [x] `token_type` default, `expires_in` as `Option<u64>` from a number or a numeric string
- [x] `from_entropy` and `TryFrom<&[u8]>` on the state and the verifier, their error types, unreserved state generation
- [x] fmt, clippy over the feature matrix, tests, no_std build
- [x] CHANGELOG; fold into cairn/spec/authorization-code-grant.md, cairn/spec/client.md, cairn/spec/coroutines.md and cairn/spec/token-lifecycle.md; log; archive
