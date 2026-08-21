---
cairn: log
change: cairn-adoption
landed: 2026-08-22
---

# Adopt Cairn, retiring docs/

docs/ held a five-line index and no document, so nothing in the repository stated current behaviour: the src/lib.rs header describes the architecture, CHANGELOG.md records releases, and neither is something a change can state a delta against. This repository now keeps cairn/spec/ (current truth, one file per capability), cairn/changes/ (in-flight proposals) and cairn/log/ (dated history), with cairn.toml as the root marker and AGENTS.md (plus CLAUDE.md) as the activation stanza. docs/ was deleted and CONTRIBUTING.md now points at cairn/.

The spec was seeded into nine capability files: `coroutines`, `authorization-code-grant`, `token-lifecycle`, `client-credentials-grant`, `device-grant`, `jwt-bearer`, `dynamic-registration`, `client` and `packaging`. That is a backfill Cairn normally discourages, done once here because the behaviour it describes already exists and later changes need something to state their deltas against. It was written from the shipped code and the src/lib.rs header, not from intent, so it records what the crate does at v0.3.0.

Two boundaries worth restating, since they are the questions this crate keeps being asked: sending an issued token to a protected resource is RFC 6750 and lives in io-http, and fetching a provider's OAuth metadata (RFC 8414, RFC 9728) is discovery and lives in io-pim-discovery. io-oauth issues tokens, nothing more. The deprecated implicit and password grants stay unimplemented, as OAuth 2.1 and RFC 9700 remove them.

The src/lib.rs header remains the entry point for the code. The spec is the behavioural truth behind it, and the forcing rule now applies: a behaviour change is not done until its delta is folded into the spec and an entry is appended here.

Capabilities moved: none. This change moved documentation, not behaviour.
