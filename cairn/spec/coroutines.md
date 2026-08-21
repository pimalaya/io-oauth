---
cairn: spec
capability: coroutines
status: current
---

# Coroutines

Every OAuth exchange in io-oauth is an I/O-free resumable state machine built on io-http. The caller owns the socket and feeds the coroutine the bytes it read, so the same logic runs blocking, async, or against in-memory buffers in tests.

### Requirement: Coroutine shape
Every coroutine SHALL expose a `new` constructor taking its typed request params and a `resume` method taking the bytes read since the last step. It SHALL NOT perform I/O itself.

### Requirement: Per-coroutine result enum
A `resume` step SHALL return the coroutine's own `Result`-suffixed enum, carrying the terminal output, a read request, a write request or an error. Each coroutine declares its own enum rather than sharing a crate-wide trait, so a step names exactly the outputs and errors that exchange can produce.

#### Scenario: Coroutine wants bytes
- GIVEN a caller pumping a token exchange
- WHEN the coroutine yields a read request
- THEN the caller reads from its own socket and resumes with the bytes it got

### Requirement: Redirects are errors
An unexpected 3xx SHALL surface as a redirect error carrying the target URL and the status code. A coroutine SHALL NOT follow a redirect itself.

### Requirement: One exchange per coroutine
A coroutine SHALL model exactly one HTTP exchange. A flow needing several exchanges (device polling, a grant followed by a refresh) SHALL be driven by the caller, which builds a fresh coroutine per exchange.

### Requirement: Clock-free
The coroutine layer SHALL read no clock. Time-dependent values (the JWT `iat`, `exp` and `nbf` claims, the polling deadline) SHALL be provided by the caller, the std client being the layer allowed to read a clock.
