# Changelog

All notable changes to `rastray` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-06-14

Maintenance release: CI hygiene and supply-chain hardening. No
functional code changes.

### Added

- Release archives are now signed with [Sigstore](https://www.sigstore.dev/)
  cosign keyless OIDC. Each `.tar.gz` and `.zip` ships with a matching
  `.cosign.bundle` sidecar that proves the artifact was built by this
  repository's tagged release workflow. Verification command and
  certificate identity documented in [`install/README.md`](install/README.md).

### Changed

- `release.yml` now follows least privilege: top-level `GITHUB_TOKEN`
  permissions are `contents: read`, with only the `binaries` and
  `installers` jobs explicitly escalating to `contents: write` to
  upload release assets. Lifts OSSF Scorecard `Token-Permissions`
  to a passing score.
- All workflows bumped to Node.js 24-compatible action runtimes ahead
  of the GitHub Actions Node 20 deprecation deadline:
  - `actions/checkout` v4.2.2 → v6.0.3
  - `actions/cache` v4 → v5.0.5
  - `softprops/action-gh-release` v2 → v3.0.0

## [0.1.0] - 2026-06-13

First public release. `rastray` is a polyglot static analysis CLI that
ships secret detection, dependency vulnerability scanning, and per-language
performance analyzers in a single binary.

### Added

#### Analyzers

- **Secret detection** — eight regex patterns out of the box: AWS access
  key (`AKIA*`), GitHub PAT (classic `ghp_*` and fine-grained
  `github_pat_*`), Slack bot (`xoxb-*`), Stripe live (`sk_live_*`),
  Google API (`AIza*`), PEM private key, npm token (`npm_*`). Shannon
  entropy filtering (default threshold 3.0) suppresses placeholders and
  example tokens; PEM headers bypass the entropy gate.
- **Dependency vulnerabilities** — parses `Cargo.lock`,
  `package-lock.json`, `requirements.txt`, and `go.sum`, then queries
  [OSV.dev](https://osv.dev) `/v1/querybatch` with per-vulnerability
  hydration. CVSS v3/v4 and GHSA textual severity mapping. Findings are
  cached for 24 h in `%LOCALAPPDATA%\rastray\osv-cache.json` (Windows) or
  `$XDG_CACHE_HOME/rastray/` (Linux); override with `$RASTRAY_CACHE_DIR`.
- **Performance** (tree-sitter ASTs) across Rust, TypeScript / JavaScript
  / TSX, Python, and Go:
  - Rust — `format!` in loops, `.clone()` on iterators inside `for`
  - TypeScript / JavaScript — `await` in loops, `new Date()` in loops
  - Python — string `+=` in loops, `time.sleep` in `async def`
  - Go — `defer` inside `for`, `fmt.Sprintf` in loops

#### Output formats

- `--format human` (default) — `miette`-rendered diagnostics with source
  spans and help text.
- `--format json` — stable schema documented in the README.
- `--format gh-actions` — GitHub Actions workflow commands so findings
  render as inline PR annotations (`error` / `warning` / `notice`).
- `--format sarif` — SARIF 2.1.0 for GitHub Code Scanning and IDE
  integrations. Severities map as Critical/High → `error`,
  Medium → `warning`, Low/Info → `note`.
- `-o, --output <FILE>` routes `json` and `sarif` payloads to disk.

#### Configuration

- `.rastray.toml` is auto-discovered up the directory tree. Override
  with `--config <FILE>` or skip with `--no-config`.
- Per-rule enable/disable and per-rule severity overrides.
- Glob-based ignore paths under `[scan.ignore]`.
- `[scan].fail_on` and matching `--fail-on <LEVEL>` flag control the
  exit code threshold independently of `--min-severity`. Accepts
  `info`, `low`, `medium`, `high`, `critical`, or `never`. Resolution
  order: CLI > config > `--min-severity` default.

#### Suppression

- Inline directives in scanned source files, language-agnostic
  (works inside `//`, `#`, or `/* */` comments):
  - `rastray-ignore: <CODE>` — suppresses the next line
  - `rastray-ignore-line: <CODE>` — suppresses the same line
  - `rastray-ignore-file: <CODE>` — suppresses the whole file
- Comma-separated code lists and the `*` wildcard are supported.

#### Distribution

- Published to <https://crates.io/crates/rastray> —
  `cargo install rastray --locked`.
- Prebuilt binaries for `x86_64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`, and
  `x86_64-pc-windows-msvc` attached to every release with SHA-256
  sidecars.
- Shell installers (`install.sh`, `install.ps1`) that download,
  verify, and extract the right archive for the host platform.

#### Examples

- [`examples/github-actions/`](examples/github-actions/) — drop-in
  workflow with inline annotations, SARIF upload, and an explicit
  severity gate.
- [`examples/config/`](examples/config/) — four sample
  `.rastray.toml` files (`minimal`, `advisory`, `strict`,
  `monorepo`).

### Security

- No `unsafe`, `unwrap`, `expect`, or `panic!` in production paths.
- TLS via `rustls` only; no OpenSSL surface area.
- Minimal default features on `tokio` and `reqwest`.
- Hardened release profile: `lto = "thin"`, `codegen-units = 1`,
  `strip = "symbols"`, `panic = "abort"`.
- Resolved RustSec advisory `RUSTSEC-2025-0023` (tokio broadcast
  soundness) by pinning `tokio >= 1.47`.

### Compatibility

- MSRV: Rust **1.86.0**.
- The JSON output is considered stable within a minor version. Schema
  additions will be called out in this changelog.

[Unreleased]: https://github.com/balangyaoejuspher/rastray/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.1
[0.1.0]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.0
