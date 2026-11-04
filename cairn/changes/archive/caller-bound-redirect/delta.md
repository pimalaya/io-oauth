---
cairn: delta
change: caller-bound-redirect
---

## MODIFIED Requirements

### Requirement: Redirect listener
The client SHALL offer a single-shot local listener that waits for the authorization redirect, answers a placeholder `200 OK` and returns the redirected URL carrying the code and state. It SHALL also accept on a listener the caller bound, so the port can be held from before the authorization URL is handed out. Tracking the PKCE verifier and the original state SHALL stay the caller's business.
