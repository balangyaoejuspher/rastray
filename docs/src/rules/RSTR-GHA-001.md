# RSTR-GHA-001 — `pull_request_target` + PR-head checkout

## Summary

A GitHub Actions workflow triggers on `pull_request_target` *and*
checks out the pull-request head (`ref: ${{ github.event.pull_request.head.sha }}`).
`pull_request_target` runs with full repo-secret access — by design,
so workflows can post comments — but combining it with a PR-head
checkout means an attacker-authored PR runs *with* the secrets,
yielding straightforward exfiltration via curl, env-dump, or any
`run:` step.

This is the most commonly exploited GHA misconfiguration class.

## Severity

`Critical`.

## Languages

GitHub Actions workflow YAML (`.github/workflows/*.yml`).

## What rastray flags

```yaml
on:
  pull_request_target:                          # ← flagged combo
    types: [opened, synchronize]

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

## What rastray deliberately does *not* flag

- `on: pull_request` — that trigger runs without secrets, so PR-head
  checkout is safe.
- `on: pull_request_target` without any PR-head checkout — useful and
  safe; the workflow operates on `main` content.

## How to fix it

Pick one of these patterns depending on what the workflow needs:

**Pattern A — read-only checks** (lint, test, build the PR's code):
use `on: pull_request`. No secrets, PR head is checked out:

```yaml
on: pull_request

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test
```

**Pattern B — labelling/commenting on the PR** (needs secrets, must
not run untrusted code): use `pull_request_target` and **do not
check out** the PR head:

```yaml
on: pull_request_target

jobs:
  label:
    permissions: { pull-requests: write }
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4         # checks out base, NOT PR head
      - run: ./scripts/label.sh
```

**Pattern C — both needed**: split into two workflows. One on
`pull_request` does the build; one on `pull_request_target` reads the
build artefact and posts a comment.

## References

- [GitHub: keeping workflows secure with pull_request_target](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [Github Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
