---
cairn: spec
capability: client-credentials-grant
status: current
---

# Client credentials grant

The RFC 6749 section 4.4 flow: the client authenticates with its own credentials and receives a token scoped to resources under its own control, no end user involved.

### Requirement: Request shape
The request body SHALL carry the grant type and the requested scope only. The client SHALL be authenticated by the token endpoint itself, typically through an HTTP Basic `Authorization` header.

### Requirement: No refresh token
The grant SHALL NOT expect a refresh token. The caller repeats the request when the token expires.

### Requirement: JWT-authenticated variant
The same grant SHALL also be reachable with a signed JWT assertion in place of a client secret, described in [jwt-bearer](./jwt-bearer.md).
