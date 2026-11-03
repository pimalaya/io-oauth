---
cairn: log
change: token-revocation
landed: 2026-11-03
---

# Token revocation

The new `rfc7009::revoke` module revokes a token: `Oauth20TokenRevokeParams` (token, `Oauth20TokenTypeHint`, client id, optional secret), the `Oauth20TokenRevoke` coroutine returning `Ok(())` on a success status, `Oauth20TokenRevokeErrorParams` on an OAuth error body, and `Oauth20TokenRevokeError::Status` on an error status without one. `Oauth20ClientStd::revoke_token` pumps it against a given endpoint.

Capabilities moved: `token-revocation` (new), `client` (One method per exchange), `packaging` (module list).

Verified: `params_send_the_hint_and_client_id`, `ok_status_revokes`, `error_body_returns_its_code` and `unavailable_without_body_returns_its_status` pass, the no_std build too.
