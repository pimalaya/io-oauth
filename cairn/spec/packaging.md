---
cairn: spec
capability: packaging
status: current
---

# Packaging

io-oauth is an I/O-free library following the Pimalaya crate conventions: a no_std core with an optional std-blocking client, dual-licensed MIT OR Apache-2.0.

### Requirement: no_std core
The crate SHALL be no_std unconditionally, pulling in alloc for its owned buffers. std SHALL be reachable only through the `client` feature.

### Requirement: Feature layering
The crate SHALL expose a `client` feature gating the std-blocking client, one feature per TLS provider (rustls-ring by default, rustls-aws, native-tls) each implying `client` and selecting the matching pimalaya-stream and io-http provider, a `vendored` feature forwarding weakly to them, and a `jwt-bearer` feature gating RS256 signing. This follows the golden rule that a feature is justified only when it changes the crate set.

### Requirement: Source layout
The source tree SHALL be organised one module per RFC (rfc6749, rfc7009, rfc7523, rfc7591, rfc7636, rfc8628), mirroring io-http, so the RFC number is the version discriminator and no `2.x` wrapper module exists. Code spanning the RFC modules SHALL live at the crate root, which today means the optional client.

### Requirement: Version-scoped naming
Every public type SHALL carry the version-scoped `Oauth20` prefix, mirroring io-http's `Http11`, and SHALL read from the largest scope down to the narrowest: the device authorization request is `Oauth20DeviceAuthRequest`, never a bare `DeviceAuthRequest`.

### Requirement: Future OAuth versions
A later OAuth version SHALL slot in as its own RFC modules alongside the existing ones, with its own client, rather than reworking these. OAuth 2.1 is largely a consolidation of RFC 6749, 6750 and 7636 with mandatory PKCE and the deprecated grants removed.

### Requirement: Deprecated grants excluded
The implicit grant (RFC 6749 section 4.2) and the resource owner password credentials grant (section 4.3) SHALL NOT be implemented: OAuth 2.1 and the security BCP (RFC 9700) remove them. Extension grants (section 4.5) are a `grant_type=<URI>` mechanism rather than a concrete flow, so there is nothing generic to ship.

### Requirement: Scope boundaries
Sending an issued token to a protected resource is RFC 6750 and belongs to io-http. Fetching a provider's OAuth metadata (RFC 8414, RFC 9728) is discovery and belongs to io-pim-discovery. io-oauth issues tokens; the consumer discovers the endpoints and uses the tokens.
