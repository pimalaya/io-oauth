---
cairn: tasks
change: live-provider-tests
---

- [ ] Decide the open questions (Microsoft certificate secrets, Fastmail registration, Google device client)
- [ ] Verify io-http logs no request or response body at debug
- [ ] tests/common.rs: logger init, env helper (empty counts as unset, `_FILE` variant), connect helper, fixture key
- [ ] tests/metadata.rs: endpoint drift check for the three providers
- [ ] tests/google.rs `anonymous::`: code exchange, refresh, JWT bearer, device auth, revoke rejections
- [ ] tests/google.rs `credentialed::`: JWT bearer grant, undelegated scope, unknown subject, revoke minted token (+ optional device auth)
- [ ] tests/microsoft.rs `anonymous::`: device auth then pending, device token, code exchange and client credentials rejections
- [ ] tests/microsoft.rs `credentialed::`: client credentials, delegated scope, JWT client assertion (+ unknown certificate)
- [ ] tests/fastmail.rs `anonymous::`: register twice (same id), loopback rejected, code exchange, refresh and revoke rejections
- [ ] Pin each "observed on first run" answer (Google revoke, Microsoft bogus device code, Fastmail revoke) with a NOTE naming the date
- [ ] Manual tier: `credentialed::refresh_seeded` per provider, documented in the file header
- [ ] .github/workflows/tests.yml: google, microsoft and fastmail jobs, credentialed steps repository-guarded, `RUST_LOG=debug`
- [ ] Map org secrets to `OAUTH_*` env vars; add `MICROSOFT_CLIENT_KEY`, `MICROSOFT_CLIENT_CERTIFICATE` if approved
- [ ] Fold the delta into spec/packaging.md, log, archive
