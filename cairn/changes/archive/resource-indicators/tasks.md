---
cairn: tasks
change: resource-indicators
---

- [x] Add `resource: Vec<Url>` to `Oauth20AuthRequestParams`, repeated on the authorization URL, replaced by a `resource` extra or endpoint parameter
- [x] Add `resource: Vec<Url>` to `Oauth20AccessTokenRequestParams`, repeated in the body
- [x] Point the `InvalidTarget` docs at the field
- [x] Tests: repeated parameters, extra precedence, body pairs
