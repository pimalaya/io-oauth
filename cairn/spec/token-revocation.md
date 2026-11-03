---
cairn: spec
capability: token-revocation
status: current
---

# Token revocation

The RFC 7009 exchange telling the authorization server a token is no longer needed.

### Requirement: Revocation request
Revoking SHALL post the token, an optional `token_type_hint` (`access_token` or `refresh_token`), the client id and the optional client secret, form-urlencoded, to the revocation endpoint.

### Requirement: Revocation response
A success status SHALL mean the token is revoked, whether or not it was valid. An error status carrying an OAuth error body SHALL reach the caller as typed error params, covering `invalid_request`, `invalid_client`, `unauthorized_client` and `unsupported_token_type` with an unknown arm; one without such a body, such as a 503 asking to retry later, SHALL be an error carrying the status.
