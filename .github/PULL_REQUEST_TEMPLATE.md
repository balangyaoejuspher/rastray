<!--
Thanks for your interest in rastray.

Before you submit this PR, please read CONTRIBUTING.md.

>>> rastray is currently CLOSED to external code contributions. <<<

Pull requests from non-maintainers will be closed without review UNLESS a
maintainer has explicitly invited a PR on a linked issue (look for the words
"PR welcome" in an issue comment).

If you have not been invited:
  - Please close this PR.
  - File an issue describing the bug or the use-case instead.
  - We promise to read it.

If you HAVE been invited, delete this comment block and fill out the form below.
-->

## Linked issue

Fixes #<!-- issue number; PRs without a linked, pre-approved issue will be closed -->

## Summary

<!-- One paragraph. What does this change and why? -->

## Checklist

- [ ] A maintainer has commented "PR welcome" (or similar) on the linked issue.
- [ ] No comments added to source code (no `//`, `///`, `//!`, `/* */`, no doc-comments, no `TODO` / `FIXME`).
- [ ] No new `unsafe`, `unwrap`, `expect`, or `panic!` in production code paths.
- [ ] `cargo fmt` clean.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean.
- [ ] `cargo test --all-features` passing locally.
- [ ] No unrelated reformatting or refactoring bundled in.
- [ ] If a dependency was added: justification, license, MSRV, and feature-flag rationale are in the PR description below.
- [ ] If a dependency was added: `default-features = false` where possible, no `native-tls` / OpenSSL.

## Dependency changes

<!-- Delete this section if no dependencies were added, removed, or upgraded. -->

| Crate | Version | Reason | Features enabled |
| ----- | ------- | ------ | ---------------- |
|       |         |        |                  |

## Testing notes

<!-- How did you verify this works? What did you NOT test? -->

## Breaking changes

<!-- Does this change any public-facing behavior (CLI flags, exit codes, JSON schema)? -->
