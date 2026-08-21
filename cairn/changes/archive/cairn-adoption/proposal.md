---
cairn: change
id: cairn-adoption
status: landed
created: 2026-08-22
---

# Adopt Cairn, retiring docs/

## Why

docs/ held nothing but an index promising future documents, so the crate had no place stating what it does today: the src/lib.rs header describes the architecture, and CHANGELOG.md records releases, but neither carries the behavioural truth a change can state a delta against.

## What

Keep the three Cairn artifacts next to the code: cairn/spec/ for current truth, cairn/changes/ for in-flight proposals and cairn/log/ for the dated history, with cairn.toml as the root marker and AGENTS.md as the activation stanza. Seed the spec from the behaviour already shipped, and delete docs/.
