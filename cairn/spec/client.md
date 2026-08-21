---
cairn: spec
capability: client
status: current
---

# Std-blocking client

The optional `client` feature ships `Oauth20ClientStd`, a ready-made pump for callers who want a working OAuth client rather than a coroutine to drive. It wraps a single boxed blocking stream and inlines the coroutine loop in each method.

### Requirement: Stream ownership
The client SHALL wrap any pre-connected `Read + Write + Send` stream, and SHALL expose a replacement setter so a caller can swap the transport between operations. Under a TLS feature it SHALL also open the connection itself, plain TCP for `http://` and implicit TLS for `https://`, rejecting any other scheme and a URL missing host or port.

### Requirement: One method per exchange
The client SHALL expose one method per OAuth exchange: authorization code exchange, refresh, client credentials, both JWT bearer exchanges, device authorization, device token poll and client registration.

### Requirement: Crate-root home
The client SHALL live at the crate root rather than under an RFC module, since it spans them. A future OAuth version would add its own client alongside, unified behind a version-agnostic wrapper only once one exists.

### Requirement: Device polling loop
The client SHALL offer a blocking device-token wait that sleeps the advertised interval, raises it by 5 seconds on `slow_down`, keeps polling while the answer is `authorization_pending`, and fails once the device code lifetime has elapsed.

### Requirement: Fresh connection per poll
Each poll SHALL open a fresh connection, authorization servers rarely keeping the socket alive between polls, while carrying over the client credentials the client already holds.

### Requirement: Redirect listener
The client SHALL offer a single-shot local listener that waits for the authorization redirect, answers a placeholder `200 OK` and returns the redirected URL carrying the code and state. Tracking the PKCE verifier and the original state SHALL stay the caller's business.

### Requirement: Clock and sleep confined here
Reading a clock and sleeping SHALL happen in this layer only, the coroutines staying clock-free. The client SHALL offer an assertion-signing convenience filling the unset `aud`, `iat` and `exp` claims from its token endpoint and the current time, over the clock-free assertion module.
