---
cairn: spec
capability: dynamic-registration
status: current
---

# Dynamic client registration

The RFC 7591 exchange registering a client against the registration endpoint an authorization server advertises in its RFC 8414 metadata, sparing the provider console entirely.

### Requirement: Registration request
The crate SHALL send the client metadata of RFC 7591 section 2: redirect URIs, token endpoint auth method, grant types, response types, client name and client URI. A public client registers with the `none` auth method and needs no secret.

### Requirement: Registration response
The response SHALL parse into either the issued client information or the error params of a rejected registration. A rejection is a value the caller reads, not a transport failure.

### Requirement: Registration sources
The crate SHALL declare the ways a client obtains its registration in preference order: dynamic registration first, then reusing the registration of a well-known public client, then manual registration through the provider console.

Dynamic registration comes first because it needs no console but requires the server to advertise a registration endpoint. Reusing a public client's registration needs no server support but borrows another application's identity. Manual registration is the universal fallback.

### Requirement: Order follows declaration
The derived ordering SHALL follow declaration order, so a pick list sorts by preference without a separate ranking table.
