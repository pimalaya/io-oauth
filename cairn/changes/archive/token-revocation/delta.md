---
cairn: delta
change: token-revocation
---

## ADDED Requirements

### Requirement: Revocation request
Revoking SHALL post the token, an optional `token_type_hint` (`access_token` or `refresh_token`), the client id and the optional client secret, form-urlencoded, to the revocation endpoint.

### Requirement: Revocation response
A success status SHALL mean the token is revoked, whether or not it was valid. An error status carrying an OAuth error body SHALL reach the caller as typed error params, covering `invalid_request`, `invalid_client`, `unauthorized_client` and `unsupported_token_type` with an unknown arm; one without such a body, such as a 503 asking to retry later, SHALL be an error carrying the status.

## MODIFIED Requirements

### Requirement: One method per exchange
The client SHALL expose one method per OAuth exchange: authorization code exchange, refresh, client credentials, both JWT bearer exchanges, device authorization, device token poll, client registration and token revocation.

## REMOVED Requirements
