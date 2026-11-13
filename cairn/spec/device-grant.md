---
cairn: spec
capability: device-grant
status: current
---

# Device authorization grant

The RFC 8628 flow for inputs-constrained clients: the client asks for a device and user code pair, shows the user code and verification URI to the end user, then polls the token endpoint until the user is done.

### Requirement: Device authorization request
The crate SHALL request a device and user code pair from the device authorization endpoint with the client id and the requested scope, form-urlencoded.

### Requirement: Device authorization response
The response SHALL carry the device code, the user code, the verification URI, the codes lifetime and the minimum polling interval, defaulting to 5 seconds when the server sends none. The complete verification URI carrying the user code SHALL be optional, Microsoft Entra sending none.

### Requirement: Bounded lifetime and interval
The device authorization response SHALL expose, next to the two numbers the server sent, the codes lifetime capped at one hour and the polling interval kept between 1 and 60 seconds, both as durations and without reading a clock. A caller that polls by itself SHALL thereby get the same bounds as the std client.

#### Scenario: Server sends an absurd interval
- GIVEN a device authorization response whose `interval` is 4000000000
- WHEN the caller asks for the polling interval
- THEN it gets 60 seconds

### Requirement: One poll per coroutine
A token poll coroutine SHALL perform exactly one poll of the token endpoint with the device code. The caller waits the interval and builds a fresh coroutine for the next attempt, usually over a fresh connection.

### Requirement: Pending is not a failure
A pending authorization SHALL surface as a successful exchange whose error code is `authorization_pending` or `slow_down`, not as a coroutine error, so the caller reads the code and decides whether to keep polling.

#### Scenario: Server asks for a slower pace
- GIVEN a caller polling at the advertised interval
- WHEN a poll answers `slow_down`
- THEN the caller raises its interval by 5 seconds and keeps polling
