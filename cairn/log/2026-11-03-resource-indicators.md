---
cairn: log
change: resource-indicators
landed: 2026-11-03
---

# Typed resource indicators

`Oauth20AuthRequestParams` and `Oauth20AccessTokenRequestParams` gained `resource: Vec<Url>` (RFC 8707), one `resource` parameter per entry: repeated on the authorization URL, where a `resource` extra or endpoint parameter replaces them, and repeated in the code exchange body. Both `InvalidTarget` codes now point at the field. Adding a public field to these literal-built structs is breaking.

Capabilities moved: `authorization-code-grant` (Resource indicators added).

Verified: `every_resource_is_its_own_parameter`, `a_resource_extra_replaces_the_typed_resources` and `every_resource_is_its_own_body_pair` pass.
