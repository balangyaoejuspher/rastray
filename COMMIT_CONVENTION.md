# Commit Convention

`rastray` follows the [**Conventional Commits 1.0.0**](https://www.conventionalcommits.org/en/v1.0.0/) specification. Every commit on `main` — and every commit in an invited PR — must match.

Three local hooks in [`.githooks/`](.githooks) enforce the project's commit rules:

| Hook         | What it checks                                                                                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pre-commit` | Runs `cargo fmt --check` on staged Rust/`Cargo.*` files, rejects any staged Rust file containing comments / `unsafe` / `unwrap` / `expect` / `panic!`, then runs `cargo clippy`. |
| `commit-msg` | Validates the commit subject against this convention.                                                                                                                           |
| `pre-push`   | Runs `cargo check --all-targets --all-features` with `-D warnings` to catch dead-code and lint errors before they hit CI.                                                       |

Enable them once per clone:

```sh
git config core.hooksPath .githooks
```

## Format

```
<type>(<optional scope>): <description>

<optional body>

<optional footer(s)>
```

### Rules

- **`<type>`** is mandatory and lowercase. See the table below.
- **`<scope>`** is optional, lowercase, in parentheses. Use a module or area name.
- **`<description>`** is mandatory: imperative mood, no trailing period, ≤ 72 characters.
- Subject line total length: **≤ 72 characters**.
- Body (if any): wrap at 72 characters, separated from subject by a blank line.
- Breaking changes: append `!` after the type/scope (`feat!:` or `feat(crawler)!:`) **and** include a `BREAKING CHANGE:` footer explaining the impact.

### Allowed types

| Type       | Use for                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `feat`     | A new user-facing feature.                                              |
| `fix`      | A bug fix.                                                              |
| `perf`     | A change that improves performance without altering behaviour.          |
| `refactor` | An internal restructure with no behaviour change and no new feature.    |
| `docs`     | Documentation only (README, PLAN, CHANGELOG, etc.).                     |
| `test`     | Adding or fixing tests, no production code change.                      |
| `build`    | Build system, `Cargo.toml`, dependencies, release profile.              |
| `ci`       | CI/CD config (`.github/workflows`, hooks, etc.).                        |
| `chore`    | Routine maintenance that doesn't fit elsewhere (gitignore, formatting). |
| `revert`   | Reverts a previous commit. Reference the reverted hash in the body.     |

Any other type will be rejected by the hook.

### Allowed scopes (suggested, not enforced)

`cli`, `crawler`, `reporter`, `modules`, `secrets`, `dependencies`, `performance`, `deps`, `docs`, `ci`, `release`.

## Examples

Good:

```
feat(crawler): hard-block .terraform and .next directories
fix(reporter): degrade gracefully when source file is unreadable
perf(crawler): pre-size mpsc channel to reduce reallocations
refactor(modules): extract registry into its own submodule
docs: add JSON schema example to README
build(deps): bump tokio 1.47 -> 1.52
ci: add cargo fmt + clippy gate to PR workflow
chore: gitignore PLAN.md
```

Breaking change:

```
feat(cli)!: rename --min-severity values to match SARIF levels

BREAKING CHANGE: `--min-severity low` is now `--min-severity note`.
The old values still parse for one minor version but emit a deprecation
warning on stderr.
```

Revert:

```
revert: feat(crawler): hard-block .terraform and .next directories

This reverts commit 0a1b2c3d4e5f.
The block was too aggressive for users running rastray inside an IaC repo.
```

## What gets rejected

The hook will reject commits where:

- The type is missing or not in the allowed list.
- The subject line is longer than 72 characters.
- The subject line ends with a period.
- The description is missing after the colon.
- The breaking-change `!` is used without a `BREAKING CHANGE:` footer.

To bypass the hook in genuine emergencies (you almost never need this):

```sh
git commit --no-verify -m "..."
```

Bypassed commits will fail CI once the lint workflow is enabled, so please don't make a habit of it.

## Why this matters

- `CHANGELOG.md` can be generated automatically (e.g. via `git-cliff`) from the commit log.
- Release tooling (`release-please`, semantic-release) can compute the next version from the commit types.
- Reviewers can scan history without reading every diff.
- It costs nothing once it's a habit.
