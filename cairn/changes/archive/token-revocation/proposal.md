---
cairn: change
id: token-revocation
status: landed
created: 2026-11-03
---

# Token revocation (RFC 7009)

## Why

The crate issues and refreshes tokens but cannot revoke them, so a consumer (Ortie's token-revocation change) has no way to retire a token it no longer needs.

## What

A new `rfc7009` module with the `revoke` coroutine: `Oauth20TokenRevokeParams` (token, optional `token_type_hint`, client id, optional secret), a 200 answer as success whatever the token's validity, an OAuth error body as typed error params (`unsupported_token_type` among the codes), and an error status without such a body (a 503 asking to retry) as an error carrying the status. `Oauth20ClientStd::revoke_token` pumps it against a given endpoint.
