# Quickstart

A two-minute path from "never heard of rastray" to "scanner is wired
into my repo's pre-commit hook and CI". Pick one install path, drop
the snippet for whichever gate you care about, done.

## 1. Install

Pick one:

```sh
# macOS, Linux — official installer (recommended)
curl -fsSL https://raw.githubusercontent.com/balangyaoejuspher/rastray/main/install/install.sh | sh

# Windows
iwr https://raw.githubusercontent.com/balangyaoejuspher/rastray/main/install/install.ps1 -useb | iex

# Any platform with Rust installed
cargo install rastray --locked
```

Verify:

```sh
rastray --version
```

## 2. Smoke-test on the current repo

```sh
rastray .
```

Default exit code rules: rastray returns `0` if there are no
findings, `1` if there are. Use `--fail-on high` to gate only on
High / Critical, `--fail-on low` to gate on anything at all, or
`--fail-on never` to always exit `0` (advisory mode).

## 3. Wire it into pre-commit

`rastray` ships a top-level `.pre-commit-hooks.yaml`. Add to your
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/balangyaoejuspher/rastray
    rev: v0.11.0
    hooks:
      - id: rastray
```

Then:

```sh
pip install pre-commit
pre-commit install
```

The `rastray` hook gates on `--fail-on high`. Swap for
`id: rastray-strict` if you want to gate on *every* finding.

The hooks use `language: system`, so `rastray` must already be on
your `PATH` (install via step 1 above). The pre-commit framework
deliberately does not `cargo install` rastray on every contributor's
machine — that would turn a one-second check into a multi-minute
Rust compile.

## 4. Wire it into CI

GitHub Actions:

```yaml
name: rastray
on: [pull_request, push]
jobs:
  rastray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -fsSL https://raw.githubusercontent.com/balangyaoejuspher/rastray/main/install/install.sh | sh
      - run: rastray . --fail-on high
```

A copy-paste-ready workflow with caching, SARIF upload, and PR-comment
output lives at
[`examples/github-actions/rastray.yml`](https://github.com/balangyaoejuspher/rastray/blob/main/examples/github-actions/rastray.yml).

## 5. Editor integration (LSP)

`rastray` ships its own Language Server. Configure your editor to
launch `rastray lsp` over stdio for inline findings on save, with no
project setup.

See the main [README](https://github.com/balangyaoejuspher/rastray#editor-integration-lsp)
for the editor-specific snippets (VS Code, Neovim, Helix, Zed,
Emacs).

## What's next

- [How to read a rastray finding](./how-to-read.md)
- [Rule catalog](./rules/RSTR-INJ-001.md) — every built-in rule, its
  detection pattern, and the safe-form counter-example.
- [Benchmarks](./benchmarks/methodology.md) — rastray vs Semgrep /
  Bandit / gosec / gitleaks / eslint-security on Juice Shop,
  NodeGoat, DVWA, RailsGoat, WebGoat, and django-DefectDojo.
