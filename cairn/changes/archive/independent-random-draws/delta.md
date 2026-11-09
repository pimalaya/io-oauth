---
cairn: delta
change: independent-random-draws
---

## ADDED Requirements

### Requirement: Random characters
The CSRF state and the PKCE code verifier SHALL draw each character independently and uniformly from its alphabet out of the OS random source, rejecting the random bytes that would favour some characters, so characters may repeat. A failing OS random source SHALL panic, since generation returns no error.

#### Scenario: Verifier longer than its alphabet
- GIVEN a caller asking for a 128-character code verifier
- WHEN the verifier is generated
- THEN it holds 128 unreserved characters, some necessarily repeated

## MODIFIED Requirements

### Requirement: CSRF state
The crate SHALL provide a random opaque state value of caller-chosen size, sent on the authorization request and echoed on the callback. The state SHALL hold exactly the requested number of VSCHAR characters, 32 by default.

### Requirement: PKCE
The crate SHALL generate a high-entropy code verifier of caller-chosen size, clamped to the 43 to 128 unreserved characters RFC 7636 section 4.1 allows, 43 by default, and derive the challenge under `plain` or `S256`, the latter being the base64url-encoded SHA-256 of the verifier. The verifier SHALL hold exactly the clamped number of characters.

### Requirement: Source layout
The source tree SHALL be organised one module per RFC (rfc6749, rfc7009, rfc7523, rfc7591, rfc7636, rfc8628), mirroring io-http, so the RFC number is the version discriminator and no `2.x` wrapper module exists. Code spanning the RFC modules SHALL live at the crate root, which today means the optional client and the private random character helper shared by the state and the PKCE verifier.

## REMOVED Requirements
