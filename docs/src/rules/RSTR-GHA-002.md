# RSTR-GHA-002 — third-party action pinned by floating tag

## Summary

A workflow references a third-party action by floating tag (`@v4`,
`@main`) instead of a full commit SHA. The action's author — or
anyone who compromises their account — can publish a new commit under
the same tag and execute arbitrary code with your repository's
secrets the next time the workflow runs. This actually happens (the
`tj-actions/changed-files` compromise in early 2025 was the most
recent industry-wide example).

Pinning to a SHA freezes the action at the bytes you reviewed.

## Severity

`Medium`. The bug requires the upstream to be compromised, but the
blast radius is total.

## Languages

GitHub Actions workflow YAML.

## What rastray flags

```yaml
- uses: actions/checkout@v4                 # ← flagged
- uses: docker/setup-buildx-action@v3       # ← flagged
- uses: codecov/codecov-action@main         # ← flagged
```

## What rastray deliberately does *not* flag

- `uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v6.0.3` —
  full 40-char commit SHA with the version as a trailing comment.
- Local actions: `uses: ./.github/actions/internal-thing`.

## How to fix it

Replace the tag with the commit SHA the tag currently points to, and
keep the version as a comment so Dependabot can update both
atomically:

```yaml
- uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v6.0.3
```

For each pin you need, grab the commit SHA with:

```sh
gh api repos/actions/checkout/git/refs/tags/v6.0.3 \
  --jq '.object.sha'   # if tag is lightweight; if annotated, follow object.url
```

(Annotated tags need one extra dereference — see
[the note in your user memory](../introduction.md#tags) for why.)

Dependabot understands the `# vX.Y.Z` trailing-comment convention and
will keep the SHA in sync with new releases automatically.

## References

- [OSSF Scorecard: Pinned-Dependencies check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies)
- [tj-actions/changed-files 2025 compromise post-mortem](https://github.com/tj-actions/changed-files/issues/2464)
- [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
