---
cairn: change
id: live-provider-tests
status: active
created: 2026-11-04
---

# Live provider tests (Google, Microsoft, Fastmail)

## Why

io-oauth has unit tests only (about 20, inside src/) and no tests/ directory: no exchange has ever been checked against a real authorization server from this repository.

Two happy paths are exercised live, but only downstream: the RFC 7523 section 2.1 JWT bearer grant against Google (service account with domain-wide delegation) and the client credentials grant with a secret against Entra, each minted by io-imap, io-smtp, io-webdav, io-msgraph and io-gmail tests to get a token. A regression there surfaces in another crate, after an io-oauth release, as a "cannot mint" panic far from the cause.

Nothing else is live-tested anywhere in the family:

- every error path: real error bodies (Google's `invalid_token` on revoke, Microsoft's `AADSTS` extras `error_codes`, `trace_id`, `correlation_id`, Fastmail's `invalid_request` for every failure, told apart only by `error_description`);
- the device grant (RFC 8628), including the `authorization_pending` arm and Microsoft's missing `verification_uri_complete`;
- dynamic client registration (RFC 7591), which only Fastmail offers;
- token revocation (RFC 7009), which Google and Fastmail offer;
- the client credentials grant with a JWT client assertion (RFC 7523 section 2.2, `private_key_jwt`), which Ortie only checks against a mock.

## What

Per-provider integration suites in tests/, shaped like io-imap's tests/gmail.rs and tests/outlook.rs: one file per provider, every test `#[ignore = "requires ..."]`, run with `--ignored`, env vars prefixed `OAUTH_`, a shared tests/common.rs, one CI job per provider.

### Two tiers per provider

Each provider file holds two modules, so CI can filter by path:

- `anonymous::` needs network access only. It uses made-up client ids, the Pimalaya public client ids (not secrets) or bogus tokens, so it touches no account and runs on every push, forks included.
- `credentialed::` needs org secrets and runs in a job guarded by `if: github.repository == 'pimalaya/io-oauth'`.

A third tier, refresh with a human-seeded refresh token, stays a manual local check (see below), never CI.

### Google (tests/google.rs)

Metadata (fetched 2026-11-04): token `https://oauth2.googleapis.com/token`, device `https://oauth2.googleapis.com/device/code`, revoke `https://oauth2.googleapis.com/revoke`, no registration endpoint.

`anonymous::`

- `code_exchange_rejected`: bogus code, made-up client id: expect `invalid_client`, typed.
- `refresh_rejected`: bogus refresh token, made-up client id: expect `invalid_client`.
- `jwt_bearer_rejected`: assertion signed with the RustCrypto fixture key already used in src/rfc7523/assertion.rs, for a made-up issuer: expect `invalid_grant`.
- `device_auth_rejected`: made-up client id: expect `invalid_client`.
- `revoke_rejected`: bogus token. RFC 7009 says 200; Google is believed to answer 400 `invalid_token`, outside the RFC code list, so it should land in the unknown arm. Pin what the first run observes.

`credentialed::` (org secret `GOOGLE_SERVICE_ACCOUNT_KEY` mapped to `OAUTH_GOOGLE_SERVICE_ACCOUNT_KEY`, or `_FILE` locally; subject `OAUTH_GOOGLE_SERVICE_ACCOUNT_SUBJECT`, default `google@pimalaya.org`)

- `jwt_bearer_grant`: delegated scope `https://mail.google.com/`: Bearer token, `expires_in` present, no refresh token, issuance instant set. Unlike the downstream mints, this asserts on the response itself.
- `jwt_bearer_grant_undelegated_scope`: a scope outside the delegation (Drive): expect `unauthorized_client`.
- `jwt_bearer_grant_unknown_subject`: `sub = nobody@pimalaya.org`: expect `invalid_grant`.
- `revoke_minted_token`: mint, revoke (expect success), then GET `https://oauth2.googleapis.com/tokeninfo?access_token=...` and expect 400 to prove the revocation took effect. Unverified that Google revokes service account access tokens: if the first run says no, drop the effect check and keep the call.
- Optional `device_auth`: only with a "TVs and Limited Input" client (`OAUTH_GOOGLE_DEVICE_CLIENT_ID` and `_SECRET`), scopes `openid email` (Google's device flow refuses Gmail, Calendar and People scopes): codes returned, then one poll answers `authorization_pending`.

### Microsoft (tests/microsoft.rs)

Metadata (fetched 2026-11-04, `/common/v2.0`): token `.../oauth2/v2.0/token`, device `.../oauth2/v2.0/devicecode`, no revocation endpoint, no registration endpoint, `private_key_jwt` supported.

`anonymous::` (public client `OAUTH_MICROSOFT_PUBLIC_CLIENT_ID`, default the Pimalaya client `ba9b19e1-973e-4d7c-aed9-848bd2fee385` from android account/Oauth.java, which has public client flows enabled)

- `device_auth_then_pending`: device authorization on `/common` with `offline_access https://outlook.office.com/IMAP.AccessAsUser.All`: `device_code`, `user_code`, `verification_uri`, `interval`, `expires_in`, and no `verification_uri_complete`. Then one `request_device_access_token`: expect the pending arm, not a failure. This is the only live check of "Pending is not a failure". It leaves an unclaimed device code that expires after 15 minutes and touches no account.
- `device_token_rejected`: bogus device code. Memory notes the non-RFC `bad_verification_code`; pin which arm it reaches.
- `code_exchange_rejected`: bogus code with the public client: expect `invalid_grant`, and the `AADSTS` extras must not break parsing.
- `client_credentials_rejected`: public client on tenant `pimalaya.onmicrosoft.com` with a bogus secret: expect `invalid_client`. It shows as a failed sign-in in the test tenant's logs only.

`credentialed::` (org secrets `MICROSOFT_TENANT_ID`, `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` mapped to `OAUTH_MICROSOFT_*`)

- `client_credentials`: scope `https://graph.microsoft.com/.default`: token, no refresh token, `ext_expires_in` ignored.
- `client_credentials_delegated_scope`: a delegated scope (`Mail.Read`) with client credentials: expect `invalid_scope`.
- `jwt_bearer_client_credentials`: needs a certificate uploaded to the "Pimalaya live tests" registration and two new org secrets, `MICROSOFT_CLIENT_KEY` (PKCS#8 PEM) and `MICROSOFT_CLIENT_CERTIFICATE` (PEM or DER, for `x5t`). This would be the first live run of `private_key_jwt` in the family.
- `jwt_bearer_client_credentials_unknown_certificate`: the fixture key with a made-up thumbprint: expect `invalid_client`. Ortie's certificate renewal hint keys on that code, so it is worth pinning live.

### Fastmail (tests/fastmail.rs)

Metadata (fetched 2026-11-04): token `https://api.fastmail.com/oauth/refresh` (sic), revoke `https://api.fastmail.com/oauth/revoke`, registration `https://api.fastmail.com/oauth/register`, grants `authorization_code` and `refresh_token` only, auth method `none`. Fastmail has no headless grant, so it only gets an `anonymous::` module, and the test account is never involved.

- `register_client`: RFC 7591 with fixed params (client name `io-oauth live tests`, redirect `org.pimalaya.oauth-tests:/redirect`, auth method `none`): a client id. Registering twice must return the same id: registration is content-addressed, which also proves runs do not pile up clients.
- `register_client_rejected`: loopback redirect `http://127.0.0.1/`: expect `invalid_redirect_uri`.
- `code_exchange_rejected`: the registered client id, a bogus code and a PKCE verifier: expect `invalid_request`, with an `error_description` that reaches the caller.
- `refresh_rejected`: bogus refresh token: expect `invalid_request`.
- `revoke_rejected`: bogus token: pin the observed answer (RFC 7009 says 200).

### Metadata drift (tests/metadata.rs, `anonymous::`)

The suites hard-code endpoints because RFC 8414 discovery belongs to io-pim-discovery, not here. One test GETs the three metadata documents and asserts the hard-coded endpoints still match, parsing only the fields it needs in a test-local struct. A provider moving an endpoint then fails one clear test instead of a dozen cryptic ones.

### Manual tier: refresh

Refresh with a real refresh token needs one human consent per provider, and Microsoft rotates refresh tokens, which CI cannot write back to a secret. So it stays a local, manual pre-release check: `credentialed::refresh_seeded` per provider reads `OAUTH_<PROVIDER>_REFRESH_TOKEN` (seeded with examples/auth_code_grant.rs), asserts a fresh access token and reports rotation without printing it. Seeding constraints:

- Google: use an Internal (Workspace) client, since a Testing-mode project expires refresh tokens after 7 days.
- Microsoft: the old token stays valid until its own 90-day sliding expiry, so re-running from the same seed works for a while.
- Fastmail: the registered reverse-DNS redirect cannot reach a desktop listener, so seed by copying the code from the browser's failed navigation (the manual resume path).

### CI

Like io-imap's tests.yml: one job per provider plus the shared nix workflow. Commands:

```sh
nix develop -c cargo test --features rustls-ring,jwt-bearer --test google -- --ignored anonymous::
nix develop -c cargo test --features rustls-ring,jwt-bearer --test google -- --ignored credentialed::
```

The credentialed steps are repository-guarded. Logging is `RUST_LOG=debug`, never trace: io-http traces bodies, and here both the request (secret, assertion) and the response (access token) are sensitive. Before turning CI on, verify that io-http logs no body at debug. Test code never prints a token: assert on shape, keep `SecretString` redacted, never `expose_secret` into a panic message.

## Out of scope

- Driving a browser for the authorization code grant: it stays interactive (examples/auth_code_grant.rs).
- RFC 8414 and RFC 9728 discovery: io-pim-discovery.
- Ortie's binary-level live suite: its own change, `live-provider-tests` in ortie's cairn.

## Open questions

- Microsoft certificate: someone has to upload a certificate to the "Pimalaya live tests" registration and add `MICROSOFT_CLIENT_KEY` and `MICROSOFT_CLIENT_CERTIFICATE` as org secrets. Without them, `jwt_bearer_client_credentials` is dropped.
- Fastmail registration writes a client record into Fastmail's registry. It is unauthenticated, idempotent and not tied to the test account, so it seems compatible with the account being pull-only, but this needs the maintainer's call.
- Google device client: does a "TVs and Limited Input" client exist in `pimalaya-510315`? If not, skip the optional test: Microsoft already covers the device grant live.
