---
cairn: change
id: caller-bound-redirect
status: landed
created: 2026-11-04
---

# Accept the redirect on a caller-bound listener

## Why

`client::await_redirect` binds its own listener from the redirect URI, so a caller handing out the authorization URL first and listening after leaves the port free in between, for another process to take. ortie's MCP server (ortie cairn/changes/mcp-server) binds the port before returning the URL and accepts on a background thread.

## What

`client::await_redirect_on(listener, redirect_uri)` accepts on a listener the caller bound; `await_redirect` binds, then calls it.
