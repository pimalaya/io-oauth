---
cairn: change
id: bounded-waits-and-date-parsing
status: landed
created: 2026-11-13
---

# Bound the device wait, the redirect listener and the date parser

## Why

Three places let a number or a peer the crate does not control decide whether the client panics or blocks (family audit of 2026-11-13, OAUTH-01, OAUTH-02, OAUTH-03).

- `Oauth20ClientStd::await_device_access_token` computes `Instant::now() + Duration::from_secs(expires_in)` and sleeps `interval` before its first deadline check, both numbers being `usize` straight from the device authorization response. An `expires_in` above the clock range panics (`overflow when adding duration to instant`), an `interval` of 4000000000 sleeps about 126 years, and an `interval` of 0 polls without pause.
- `parse_http_date` runs Howard Hinnant's algorithm in `u64`. `31 Dec 1969` gives 719467 - 719468, year `0000` underflows at `year - 1` and day `00` at `day - 1`: a panic with overflow checks, a wrapped `issued_at` near `u64::MAX` without, which reads as a token that never expires. It runs on every 2xx token response.
- `await_redirect_on` takes the first connection, reads its first line without timeout or cap, returns whatever that line holds and answers "Authorization succeeded!" before the caller validated anything. A stray request (a favicon fetch, another local process, a page of the user's browser reaching the loopback port) ends the wait while the real redirect finds nobody; a peer that sends nothing or no newline blocks the call for ever and grows the line without bound; a redirect carrying `error=access_denied` is told it succeeded; a target such as `@host/path` moves the returned URL to another host.

## What

- `Oauth20DeviceAuthSuccessParams` gains two clock-free accessors: `lifetime` (the `expires_in` capped at one hour) and `poll_interval` (the `interval` kept between 1 and 60 seconds), both `core::time::Duration`. The raw fields stay what the server sent. A caller polling by itself gets the same bounds as the std client.
- The device wait takes both from the accessors, measures the elapsed time from its start (no `Instant + Duration`), sleeps the shorter of the interval and the time left, and raises the interval with a saturating add. The `slow_down` raise stays uncapped, as RFC 8628 section 3.5 words it, the time left bounding every sleep.
- `parse_http_date` computes in `i64` with euclidean division and returns `None` on a day zero and on any date before the epoch.
- The redirect listener loops on `accept` until a `GET` in origin form to the path of the redirect URI carrying a `code` or an `error` (RFC 6749 sections 4.1.2 and 4.1.2.1). A connection gets 5 seconds in total and 8 KiB to send its request line. Anything else is answered `404 Not Found` and dropped. The `200 OK` page says the response was received, nothing about the outcome, and failing to write it no longer loses the redirect.
- `Oauth20ClientStdError::InvalidRedirectRequest` is removed: a malformed request no longer ends the wait, so nothing returns it. This is the one break.

Moving the polling policy into an I/O-free coroutine that yields a wait is left out: it is a pending decision against the "One poll per coroutine" requirement. So is moving the date parser to io-http.

Known limit, unchanged: the listener does not know the state the caller sent, so a request forged to the redirect path with any `code` still ends the wait and fails the caller's state check. Closing it means passing the state to the listener, an API change.
