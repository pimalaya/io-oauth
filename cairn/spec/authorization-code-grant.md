---
cairn: spec
capability: authorization-code-grant
status: current
---

# Authorization code grant

The RFC 6749 section 4.1 flow: the user authorizes in a browser, the server redirects back with a code, and the client exchanges that code for a token. PKCE (RFC 7636) and the CSRF state (RFC 6749 section 10.12) harden it.

### Requirement: Authorization URL
The crate SHALL build the authorization URL from typed fields: client id, redirect URI, scope, state and the optional PKCE code challenge. It SHALL also accept free-form extra query parameters for provider-specific values (Google's `access_type`, Microsoft's `tenant`).

### Requirement: Parameter precedence
Extra parameters SHALL override equally-named typed defaults, and parameters already present in the endpoint URL SHALL take final precedence over both.

### Requirement: CSRF state
The crate SHALL provide a random opaque state value of caller-chosen size, sent on the authorization request and echoed on the callback.

### Requirement: Response validation
Parsing the redirected URL SHALL yield either the authorization code or a typed error response. When the caller passes an expected state, validation SHALL fail on a missing state and on a mismatching one; when it passes none, the state SHALL NOT be checked.

#### Scenario: Mismatching state
- GIVEN a caller that generated a state for the authorization request
- WHEN the callback URL carries a different state
- THEN validation fails rather than returning the code

### Requirement: Authorization error codes
The authorization error response SHALL carry a typed error code covering the RFC 6749 section 4.1.2.1 set plus the RFC 8707 `invalid_target`, with an unknown arm keeping any unregistered code verbatim.

### Requirement: Code exchange
The code SHALL be exchanged against the token endpoint with the authorization code, the redirect URI when the authorization request carried one, the client id, the optional client secret for a confidential client and the PKCE code verifier when the flow uses PKCE. The body SHALL be form-urlencoded.

### Requirement: Resource indicators
The authorization request and the code exchange SHALL carry an optional list of RFC 8707 resource indicators, sent as one `resource` parameter each and omitted when empty. On the authorization URL, an extra parameter or an endpoint parameter named `resource` SHALL replace the typed list.

### Requirement: PKCE
The crate SHALL generate a high-entropy code verifier of caller-chosen size, clamped to the 43 to 128 unreserved characters RFC 7636 section 4.1 allows, and derive the challenge under `plain` or `S256`, the latter being the base64url-encoded SHA-256 of the verifier.
