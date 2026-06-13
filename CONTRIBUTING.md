# Contributing to rastray

> **Heads up — `rastray` is currently source-available but closed to external code contributions.**
>
> The repository is published under MIT/Apache-2.0 so that anyone can read it, fork it, learn from it, and run it. However, **pull requests from non-maintainers will be closed without review** during the current development phase. This is a deliberate choice while the architecture is still settling.

This document exists so that, when contributions *do* open up, the rules are already on record — and so that until then, you know exactly what kinds of interaction *are* welcome.

---

## What is welcome right now

- **Bug reports.** If `rastray` panics, mis-classifies a file, mis-renders a finding, or behaves differently than the README documents, please file an issue.
- **Security reports.** Follow [`SECURITY.md`](SECURITY.md) — do not file these as public issues.
- **Feature requests and design discussion.** Open a GitHub Discussion or issue. Concrete use-cases are much more useful than abstract suggestions.
- **Forks.** Fork freely under the MIT/Apache-2.0 terms. You do not need permission.

## What is not accepted right now

- **Pull requests for new features, refactors, or "drive-by" cleanups.** These will be closed politely and unmerged. Please don't take it personally — it is a project-management decision, not a judgement of the work.
- **Pull requests that fix typos or formatting only.** File an issue instead; the maintainer will fold the fix into the next commit.
- **Pull requests for new analyzers.** The `Analyzer` trait is still in flux. Adding analyzers from outside before it stabilises creates churn for everyone.

The only exception is a **pre-approved PR**: if a maintainer has commented on an issue with the words *"PR welcome"* (or explicitly invited you), then a PR against that issue will be reviewed under the rules below.

---

## Filing a good issue

A useful issue contains:

1. **What you ran** — the exact `rastray` invocation, including flags.
2. **What you expected.**
3. **What actually happened** — copy-paste the output, not a screenshot, where possible.
4. **Environment** — OS, `rustc --version`, `rastray --version`.
5. **A minimal reproducer** if it's not trivially obvious.

Use the issue templates in [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE) when available.

---

## Rules for pre-approved pull requests

If — and only if — a maintainer has invited you to send a PR:

### Style

- **No comments in source code.** This project deliberately ships zero comments. No `//`, `///`, `//!`, `/* */`, no doc-comments, no `TODO` / `FIXME` / `NOTE`. Code must be self-documenting via clear naming. PRs that introduce comments will be sent back for cleanup.
- **No `unsafe`.** None. There is no use case for it in this codebase.
- **No `unwrap` / `expect` / `panic!`** in production code paths. Return `Result` and propagate. Tests may use `expect` with a meaningful message.
- Format with `cargo fmt` before pushing.
- Lint clean: `cargo clippy --all-targets --all-features -- -D warnings`.
- Tests pass: `cargo test --all-features`.

### Scope

- One logical change per PR. If you find yourself writing "and also" in the description, split the PR.
- Don't bundle dependency upgrades with feature work.
- Don't reformat files you didn't otherwise change.

### Dependencies

- Any new dependency must be justified in the PR description against the existing dependency budget. Include:
  - What the dependency provides that the standard library or an existing dependency does not.
  - The dependency's license, MSRV, maintenance status, and download count.
  - The feature flags you're enabling and why (always prefer `default-features = false`).
- TLS additions must use `rustls`, not `native-tls` / OpenSSL.

### Commits

- Follow the [**Conventional Commits**](COMMIT_CONVENTION.md) specification. The repo ships a `commit-msg` hook that enforces this — enable it with `git config core.hooksPath .githooks`.
- Write commit messages in the imperative mood: *"Add Go manifest classifier"*, not *"Added"* or *"Adds"*.
- Squash WIP / fixup commits before requesting review.
- Reference the issue number in the description: `Fixes #123`.

### Licensing

By submitting a contribution, you agree that it will be dual-licensed under the MIT and Apache-2.0 licenses already covering the project. See the `License` section of [`README.md`](README.md).

---

## Development setup

```sh
git clone https://github.com/balangyaoejuspher/rastray.git
cd rastray
cargo build
cargo test
```

Prerequisites match the README: Rust ≥ 1.86.0 and a working C/C++ toolchain (MSVC Build Tools on Windows, Xcode CLT on macOS, `build-essential` on Linux).

---

## Code of Conduct

Be respectful. Disagreements are fine; personal attacks are not. The maintainer reserves the right to lock issues, close PRs, and block users at their discretion. A formal Code of Conduct will be added if the project's surface area grows enough to need one.

---

## Release process (maintainer)

Releases are tag-driven and run via [`.github/workflows/release.yml`](.github/workflows/release.yml):

1. Land all PRs for the release on `main`.
2. Bump `version` in [`Cargo.toml`](Cargo.toml). Run `cargo update -p rastray` so `Cargo.lock` agrees.
3. In [`CHANGELOG.md`](CHANGELOG.md), rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` section above it. Update the link references at the bottom of the file.
4. Open a release-prep PR titled `chore(release): vX.Y.Z` and merge it.
5. Tag the merge commit: `git tag -s vX.Y.Z -m "vX.Y.Z"` and `git push origin vX.Y.Z`.
6. The `release` workflow runs `cargo fmt --check`, `cargo clippy`, `cargo test`, `cargo package --locked`, then `cargo publish --locked` against `crates.io`. Verify on <https://crates.io/crates/rastray>.

Dry-run before tagging: trigger the workflow manually with `dry_run = true` (the default) to run everything except the upload step.

A `CARGO_REGISTRY_TOKEN` secret must be configured on the `crates-io` GitHub Environment. The token should be a scoped publish token for the `rastray` crate, not a personal master token.
