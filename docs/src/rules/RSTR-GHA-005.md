# RSTR-GHA-005 — `actions/checkout` with `persist-credentials: true`

## Summary

`actions/checkout` defaults to `persist-credentials: true`, which
writes the auto-provisioned `GITHUB_TOKEN` (with `contents: write` if
the workflow has it) into the `.git/config` of the checkout. Any
later step that runs `git push`, or any tool that reads
`.git/config`, sees that token.

For most workflows this is wasted attack surface — the workflow only
needs the token at the moment it actually pushes back, which it
usually doesn't.

## Severity

`Low`. The token is short-lived and limited to the repo, but
defence-in-depth says don't leak it to unrelated steps.

## Languages

GitHub Actions workflow YAML.

## What rastray flags

```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: true                       # ← flagged
```

Also fires on the implicit default when the workflow needs
`contents: write` and you never set `persist-credentials: false`.

## What rastray deliberately does *not* flag

- Explicit `persist-credentials: false`.
- Workflows that actually need to push (release workflows, doc
  deploys) — suppress per-line with a comment.

## How to fix it

Set the option explicitly to `false` unless you need to push:

```yaml
- uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v6.0.3
  with:
    persist-credentials: false
```

For the rare workflow that does need to push, scope the token
minimally with `permissions:` and document the exception:

```yaml
permissions:
  contents: write

steps:
  # rastray-ignore: RSTR-GHA-005 — release workflow tags + pushes back to main
  - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v6.0.3
    with:
      persist-credentials: true
```

## References

- [`actions/checkout` README](https://github.com/actions/checkout#readme)
- [GitHub: GITHUB_TOKEN permissions](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
