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
The crate SHALL provide a random opaque state value of caller-chosen size, sent on the authorization request and echoed on the callback. A generated state SHALL hold exactly the requested number of unreserved characters, 32 by default. A state built from bytes or deserialized SHALL hold one or more VSCHAR characters, as RFC 6749 appendix A.5 defines it, and be refused otherwise.

### Requirement: Response validation
Parsing the redirected URL SHALL yield either the authorization code or a typed error response. When the caller passes an expected state, validation SHALL fail on a missing state and on a mismatching one; when it passes none, the state SHALL NOT be checked.

#### Scenario: Mismatching state
- GIVEN a caller that generated a state for the authorization request
- WHEN the callback URL carries a different state
- THEN validation fails rather than returning the code

### Requirement: Issuer validation
The success params SHALL carry the RFC 9207 `iss` parameter when the response names one. When the caller passes an expected issuer, validation SHALL refuse a code whose response names another one, the two being compared as strings (RFC 9207 section 2.4); a response naming none SHALL pass, and when the caller passes no issuer the parameter SHALL NOT be checked. An error response SHALL be returned as such whatever issuer it names. Requiring `iss` from a server that advertises it SHALL stay the caller's check on the success params.

#### Scenario: Code from another server
- GIVEN a caller that started the flow against one authorization server
- WHEN the callback URL carries a code and the `iss` of another server
- THEN validation fails with the issuer it named rather than returning the code

### Requirement: Authorization error codes
The authorization error response SHALL carry a typed error code covering the RFC 6749 section 4.1.2.1 set plus the RFC 8707 `invalid_target`, with an unknown arm keeping any unregistered code verbatim.

### Requirement: Code exchange
The code SHALL be exchanged against the token endpoint with the authorization code, the redirect URI when the authorization request carried one, the client id, the optional client secret for a confidential client and the PKCE code verifier when the flow uses PKCE. The body SHALL be form-urlencoded.

### Requirement: Resource indicators
The authorization request and the code exchange SHALL carry an optional list of RFC 8707 resource indicators, sent as one `resource` parameter each and omitted when empty. On the authorization URL, an extra parameter or an endpoint parameter named `resource` SHALL replace the typed list.

### Requirement: PKCE
The crate SHALL generate a high-entropy code verifier of caller-chosen size, clamped to the 43 to 128 unreserved characters RFC 7636 section 4.1 allows, 43 by default, and derive the challenge under `plain` or `S256`, the latter being the base64url-encoded SHA-256 of the verifier. The verifier SHALL hold exactly the clamped number of characters. A verifier built from bytes or parsed from a string SHALL be refused unless it holds 43 to 128 unreserved characters.

### Requirement: Random characters
The CSRF state and the PKCE code verifier SHALL draw each character independently and uniformly from the 66 unreserved characters out of the OS random source, rejecting the random bytes that would favour some characters, so characters may repeat. A failing OS random source SHALL panic, since generation returns no error.

### Requirement: Caller-supplied randomness
The state and the code verifier SHALL each be buildable without the `client` feature from 32 random bytes the caller drew, base64url-encoded into 43 characters, the recipe of RFC 7636 section 4.1. A caller that cannot afford the generator's panic SHALL be able to draw the bytes itself and handle the failure.

#### Scenario: Verifier longer than its alphabet
- GIVEN a caller asking for a 128-character code verifier
- WHEN the verifier is generated
- THEN it holds 128 unreserved characters, some necessarily repeated
