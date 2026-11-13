---
cairn: delta
change: request-and-response-hardening
---

## ADDED Requirements

### Requirement: Issuer validation
The success params SHALL carry the RFC 9207 `iss` parameter when the response names one. When the caller passes an expected issuer, validation SHALL refuse a code whose response names another one, the two being compared as strings (RFC 9207 section 2.4); a response naming none SHALL pass, and when the caller passes no issuer the parameter SHALL NOT be checked. An error response SHALL be returned as such whatever issuer it names. Requiring `iss` from a server that advertises it SHALL stay the caller's check on the success params.

#### Scenario: Code from another server
- GIVEN a caller that started the flow against one authorization server
- WHEN the callback URL carries a code and the `iss` of another server
- THEN validation fails with the issuer it named rather than returning the code

### Requirement: Caller-supplied randomness
The state and the code verifier SHALL each be buildable without the `client` feature from 32 random bytes the caller drew, base64url-encoded into 43 characters, the recipe of RFC 7636 section 4.1. A caller that cannot afford the generator's panic SHALL be able to draw the bytes itself and handle the failure.

### Requirement: Error status without an OAuth body
A non-success status whose body is not the OAuth error object SHALL surface, in every coroutine, as an error carrying the status code, so a caller tells a 503 or a 429 from a malformed reply. A success status whose body does not parse SHALL stay a parse error.

#### Scenario: Gateway answers in HTML
- GIVEN a caller pumping a token exchange
- WHEN the endpoint answers 503 with an HTML page
- THEN the coroutine ends with an error carrying 503

### Requirement: Lenient success parsing
A success response SHALL NOT be dropped over the two deviations servers are known for: a missing `token_type` SHALL default to `Bearer`, and the lifetime SHALL be read from a number or from a numeric string, into 64 bits. Any other shape of the lifetime SHALL stay a parse error.

### Requirement: Client authentication
When the client holds a secret, it SHALL authenticate with HTTP Basic, the client id and the secret being form-urlencoded before they are joined and base64-encoded (RFC 6749 section 2.3.1). Letters, digits and `*-._~` SHALL stay literal, a space SHALL become `+` and any other byte its percent-encoding. The form encoding would escape `~` as well, but RFC 3986 leaves it unreserved: a server that decodes the credentials reads both spellings alike, while one that compares them raw only knows the literal one, so an id or a secret made of unreserved characters SHALL NOT change on the wire. Section 2.3 allows one authentication method per request: the caller SHALL NOT set the `client_secret` of the request params as well, which the client does not enforce.

## MODIFIED Requirements

### Requirement: CSRF state
The crate SHALL provide a random opaque state value of caller-chosen size, sent on the authorization request and echoed on the callback. A generated state SHALL hold exactly the requested number of unreserved characters, 32 by default. A state built from bytes or deserialized SHALL hold one or more VSCHAR characters, as RFC 6749 appendix A.5 defines it, and be refused otherwise.

### Requirement: PKCE
The crate SHALL generate a high-entropy code verifier of caller-chosen size, clamped to the 43 to 128 unreserved characters RFC 7636 section 4.1 allows, 43 by default, and derive the challenge under `plain` or `S256`, the latter being the base64url-encoded SHA-256 of the verifier. The verifier SHALL hold exactly the clamped number of characters. A verifier built from bytes or parsed from a string SHALL be refused unless it holds 43 to 128 unreserved characters.

### Requirement: Random characters
The CSRF state and the PKCE code verifier SHALL draw each character independently and uniformly from the 66 unreserved characters out of the OS random source, rejecting the random bytes that would favour some characters, so characters may repeat. A failing OS random source SHALL panic, since generation returns no error.

### Requirement: Redirect listener
The client SHALL offer a single-shot local listener that waits for the authorization redirect, answers a placeholder `200 OK` claiming no outcome and returns the redirected URL carrying the code and state. Only a `GET` in origin form to the path of the redirect URI, carrying a `code` or an `error` parameter, SHALL end the wait. Any other connection SHALL be answered `404 Not Found` and dropped, the wait going on, each connection getting 5 seconds in total to send a request line of at most 8 KiB. Connections SHALL be served one at a time. The client SHALL also accept on a listener the caller bound, so the port can be held from before the authorization URL is handed out. When the caller passes the state it sent, only a request echoing it SHALL end the wait, so a request forged to the redirect path is dropped like any other; when it passes none, such a request ends the wait and fails the caller's state check. Tracking the PKCE verifier and validating the response SHALL stay the caller's business.

#### Scenario: Forged request before the redirect
- GIVEN a caller waiting on the redirect path `/cb` with the state it sent
- WHEN a first connection sends a code with another state and a second one sends the redirect
- THEN the first is answered `404 Not Found` and the wait returns the URL of the second

### Requirement: Secret handling
Secret-bearing values (client secret, issued tokens, device code, signed assertion, CSRF state) SHALL be carried in secrecy wrappers, so a debug rendering never prints them and exposure is an explicit call. Request params carrying a secret SHALL NOT implement `Display`: their form body SHALL come from an explicit body builder. A coroutine's debug rendering SHALL NOT print the request it holds.

## REMOVED Requirements
