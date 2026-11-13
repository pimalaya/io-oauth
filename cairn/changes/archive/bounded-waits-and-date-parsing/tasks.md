---
cairn: tasks
change: bounded-waits-and-date-parsing
---

# Tasks

- [x] Tests on the old code, confirmed failing: device lifetime beyond the clock range, device interval beyond the lifetime, date before the epoch, year zero, day zero, seven listener cases (another path, no `code` or `error`, not a `GET`, target outside origin form, line over the cap, silent connection, error redirect answered as a success)
- [x] `Oauth20DeviceAuthSuccessParams::lifetime` and `poll_interval`, with their clamp tests
- [x] `await_device_access_token` on the accessors: elapsed time, sleep no longer than the time left, saturating raise
- [x] `parse_http_date` in `i64`, `None` on day zero and before the epoch
- [x] `await_redirect_on`: accept loop, 5 second and 8 KiB bound, `404 Not Found` for the rest, neutral `200 OK` page
- [x] `Oauth20ClientStdError::InvalidRedirectRequest` removed
- [x] fmt, clippy over the feature matrix, tests, no_std build
- [x] CHANGELOG; fold into cairn/spec/client.md, cairn/spec/device-grant.md and cairn/spec/token-lifecycle.md; log; archive
