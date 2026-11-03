---
cairn: change
id: resource-indicators
status: landed
created: 2026-11-03
---

# Typed resource indicators (RFC 8707)

## Why

A server bound to a resource (Fastmail's JMAP API) refuses an authorization request without an RFC 8707 `resource` parameter, answering `invalid_target`. The crate typed that failure but no request carried the parameter, so every consumer routed it through `extras` and learned the trap again. Ortie's discovery-layering change asked for the typed field.

## What

`Oauth20AuthRequestParams` and `Oauth20AccessTokenRequestParams` gain `resource: Vec<Url>`, one `resource` parameter per entry, empty sending none (RFC 8707 allows several). On the authorization URL an extra or an endpoint parameter named `resource` replaces the typed list, following the existing precedence. The `InvalidTarget` docs point at the field.
