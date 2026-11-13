---
cairn: change
id: request-and-response-hardening
status: landed
created: 2026-11-13
---

# Harden what the client sends and what it accepts

## Why

Six defects from the family audit of 2026-11-13, each small, all on the path between a caller's secrets and a server's answer.

- OAUTH-07: the std client builds its Basic credentials from the raw client id and secret. RFC 6749 section 2.3.1 has both form-urlencoded first, so an id holding `:` or a secret holding `+` or `%` reads differently on a compliant server, which answers `invalid_client`.
- OAUTH-12: the authorization response parser has no `iss` arm and `validate` takes the state only, so a client talking to several authorization servers has no mix-up defence (RFC 9207) unless it parses the redirect a second time itself.
- OAUTH-03, residual of the bounded-waits-and-date-parsing change: the redirect listener does not know the state the caller sent, so a request forged to the redirect path ends the wait, and the real redirect finds nobody.
- OAUTH-04: six request params types (authorization code exchange, refresh, device poll, revocation, both JWT bearer exchanges) implement `Display` as their body serializer, so `{params}` in a log or an error prints the code, the verifier, the client secret, the refresh token, the device code or the assertion, on types whose `Debug` redacts them. `Oauth20AccessTokenRequest` derives `Debug` over the HTTP coroutine, which prints the pending request bytes.
- OAUTH-05: a non-success status whose body is not the OAuth error object (a 503 or a 429 with an HTML page, an empty body) ends in `ParseHttpResponse`, the status reaching a `trace!` only. The caller cannot tell "retry later" from "malformed reply". Revocation already returns `Status(u16)`.
- OAUTH-06: the success params require `token_type` and a numeric `expires_in`, as RFC 6749 section 5.1 words it. A server sending `"expires_in": "3600"` or no `token_type` gets its 2xx answer dropped, access and refresh token with it; where refresh tokens rotate, the previous one is already spent.
- OAUTH-11: without the `client` feature, the only way to build a state is serde and the only way to build a verifier is `FromStr`, which accepts any length although RFC 7636 section 4.1 asks for 43 to 128 characters. Nothing takes the caller's own randomness. The generated state draws from all 95 VSCHAR characters, space, quotes, `<`, `&` and `+` included.

## What

- Basic credentials: the client id and the secret are form-urlencoded before `HttpAuthBasic`, every RFC 3986 unreserved character staying literal (`form_urlencoded::byte_serialize` with the `~` put back), so a secret made of unreserved characters does not change on the wire and a server comparing the raw credentials keeps accepting it. The double authentication (Basic from the client, `client_secret` in the params) is documented on `Oauth20ClientStd::client_secret`, not refused: refusing would break a setup a tolerant server accepts today.
- Issuer: `Oauth20AuthSuccessParams` gains `iss`, and `Oauth20AuthParams::validate` takes `expected_issuer: Option<&str>`. A code whose response names another issuer fails with `IssuerMismatch`, carrying the issuer named. Strings are compared as they are (RFC 9207 section 2.4). A response naming none passes; error responses are returned as before.
- Listener: `await_redirect` and `await_redirect_on` take `expected_state: Option<&Oauth20State>`. With a state, a request that does not echo it is answered `404 Not Found` like any stray one.
- Secrets: the six `Display` impls go, each type gets `to_body(&self) -> Vec<u8>` next to its serializer method, and the coroutines call it. `Oauth20AccessTokenRequest` gets a hand-written `Debug` that prints no field. The two params types without a secret (client credentials, device authorization request) keep `Display`.
- Status: the eight errors that lacked it gain `Status(u16)`, returned when the body of a non-success response does not parse as the error object. A 2xx whose body does not parse stays `ParseHttpResponse`.
- Token response: `token_type` defaults to `Bearer`, `expires_in` becomes `Option<u64>` and is read from a number or a numeric string. Anything else in `expires_in` still fails.
- Randomness: `from_entropy(&[u8; 32])` on the state and on the verifier, base64url-encoding into 43 characters, available without `client`. `TryFrom<&[u8]>` on both, with `Oauth20StateError` (one or more VSCHAR) and `Oauth20PkceCodeVerifierError` (43 to 128 unreserved); the state's `Deserialize` and the verifier's `FromStr` go through them. The generated state draws from the 66 unreserved characters.

Left out: a fallible generator. The panic on a failing OS random source is a recorded choice (independent-random-draws, 2026-11-09), and `from_entropy` gives a caller the fallible path with its own draw.
