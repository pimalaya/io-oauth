---
cairn: log
change: caller-bound-redirect
landed: 2026-11-04
---

# Accept the redirect on a caller-bound listener

Added `client::await_redirect_on`, accepting the authorization redirect on a `TcpListener` the caller bound; `await_redirect` binds and calls it. For ortie's MCP server, which holds the port from before it returns the authorization URL.

Capabilities moved: `client` (Redirect listener modified).

Verified: `a_caller_bound_listener_returns_the_redirect` in src/client.rs.
