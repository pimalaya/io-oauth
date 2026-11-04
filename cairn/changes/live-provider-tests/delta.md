---
cairn: delta
change: live-provider-tests
---

## ADDED Requirements

### Requirement: Live provider suites
The crate SHALL carry one ignored integration suite per provider (Google, Microsoft, Fastmail) under tests/, run with `--ignored`. Each suite SHALL split into an `anonymous` module, which needs network access only and touches no account, and a `credentialed` module, which needs org secrets and runs in CI only in the upstream repository. Live runs SHALL log at debug at most, and no test SHALL print a token, secret or assertion.

### Requirement: Endpoint drift check
A live test SHALL compare the endpoints the provider suites hard-code with each provider's published authorization server metadata.

## MODIFIED Requirements

## REMOVED Requirements
