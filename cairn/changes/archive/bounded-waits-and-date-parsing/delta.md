---
cairn: delta
change: bounded-waits-and-date-parsing
---

## ADDED Requirements

### Requirement: Bounded lifetime and interval
The device authorization response SHALL expose, next to the two numbers the server sent, the codes lifetime capped at one hour and the polling interval kept between 1 and 60 seconds, both as durations and without reading a clock. A caller that polls by itself SHALL thereby get the same bounds as the std client.

#### Scenario: Server sends an absurd interval
- GIVEN a device authorization response whose `interval` is 4000000000
- WHEN the caller asks for the polling interval
- THEN it gets 60 seconds

## MODIFIED Requirements

### Requirement: Device polling loop
The client SHALL offer a blocking device-token wait that sleeps the bounded polling interval, raises it by 5 seconds on `slow_down`, keeps polling while the answer is `authorization_pending`, and fails once the bounded device code lifetime has elapsed. No sleep SHALL outlast the time left on that lifetime, and no number the server chose SHALL reach arithmetic that can panic.

### Requirement: Redirect listener
The client SHALL offer a single-shot local listener that waits for the authorization redirect, answers a placeholder `200 OK` claiming no outcome and returns the redirected URL carrying the code and state. Only a `GET` in origin form to the path of the redirect URI, carrying a `code` or an `error` parameter, SHALL end the wait. Any other connection SHALL be answered `404 Not Found` and dropped, the wait going on, each connection getting 5 seconds in total to send a request line of at most 8 KiB. Connections SHALL be served one at a time. The client SHALL also accept on a listener the caller bound, so the port can be held from before the authorization URL is handed out. Tracking the PKCE verifier and the original state SHALL stay the caller's business, so a request forged to the redirect path still ends the wait and fails the caller's state check.

#### Scenario: Stray request before the redirect
- GIVEN a caller waiting on the redirect path `/cb`
- WHEN a first connection asks for `/favicon.ico` and a second one sends the redirect
- THEN the first is answered `404 Not Found` and the wait returns the URL of the second

### Requirement: Date parsing
The `Date` header SHALL be parsed as an IMF-fixdate of exactly 29 ASCII bytes, yielding nothing on any structural deviation, on a day zero and on a date before the Unix epoch. Day-of-month legality SHALL NOT be checked beyond that, origin servers being trusted to send well-formed dates.

## REMOVED Requirements
