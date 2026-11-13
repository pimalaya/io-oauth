---
cairn: spec
capability: token-lifecycle
status: current
---

# Token lifecycle

The token endpoint response shared by every grant (RFC 6749 section 5), and the refresh exchange trading a refresh token for a fresh access token (section 6).

### Requirement: Token response
The token endpoint response SHALL parse into either the success params (access token, token type, lifetime, refresh token, granted scope) or the error params (code, description, URI). A response is a value, not an error: an OAuth-level rejection SHALL reach the caller as parsed error params rather than as a transport failure.

### Requirement: Issuance instant
The success params SHALL carry the issuance instant in Unix epoch seconds, read from the HTTP `Date` header and left unset when the server sent none. It sits outside the OAuth specs so the caller can compute expiry as issuance plus lifetime against its own clock, the crate reading none.

### Requirement: Date parsing
The `Date` header SHALL be parsed as an IMF-fixdate of exactly 29 ASCII bytes, yielding nothing on any structural deviation, on a day zero and on a date before the Unix epoch. Day-of-month legality SHALL NOT be checked beyond that, origin servers being trusted to send well-formed dates.

### Requirement: Token error codes
The token error response SHALL carry a typed error code covering the RFC 6749 section 5.2 set, the RFC 8628 section 3.5 device codes (`authorization_pending`, `slow_down`, `authorization_declined`, `expired_token`), the RFC 8707 `invalid_target` and the non-standard Microsoft Entra codes, with an unknown arm keeping any unregistered code verbatim.

### Requirement: Wire spellings preserved
An error code SHALL keep its wire spelling even where the crate otherwise shortens identifiers, so `authorization_pending` and `authorization_declined` are never renamed to match the `auth` prefix used elsewhere.

### Requirement: Refresh
Refreshing SHALL send the refresh token with the client id, the optional client secret and an optional scope narrowing the original one. A convenience constructor SHALL build the params from a client id and refresh token alone.

### Requirement: Secret handling
Secret-bearing values (client secret, issued tokens, device code, signed assertion, CSRF state) SHALL be carried in secrecy wrappers, so a debug rendering never prints them and exposure is an explicit call.
