# Changelog

All notable changes to `rastray` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-13

### Added

- **Phase 6 — Configuration & suppression**
  - `.rastray.toml` configuration file with rule enable/disable, per-rule severity overrides, ignore-path globs, and `fail_on` threshold. Auto-discovered up the directory tree; overridable via `--config <FILE>`, skippable via `--no-config`.
  - Inline suppression directives in scanned files: `rastray-ignore` (next line), `rastray-ignore-line` (same line), `rastray-ignore-file` (whole file). Comma-separated code lists and the `*` wildcard are supported.
  - `--fail-on <LEVEL>` CLI flag and matching `[scan].fail_on` config field. Accepted values: `info`, `low`, `medium`, `high`, `critical`, `never`. Resolution order: CLI > config > `--min-severity` default.
  - Four drop-in example configurations under [`examples/config/`](examples/config/) (`minimal`, `advisory`, `strict`, `monorepo`).
- **Phase 5 — Output formats**
  - `--format gh-actions` emits GitHub Actions workflow commands so findings render as inline PR annotations (`error` / `warning` / `notice`).
  - `--format sarif` emits SARIF 2.1.0 documents for GitHub Code Scanning and IDE consumers. Severity → SARIF level: Critical/High → `error`, Medium → `warning`, Low/Info → `note`.
  - `-o, --output <FILE>` flag routes JSON and SARIF output to disk (no effect on `human` / `gh-actions`).
  - Drop-in [`examples/github-actions/rastray.yml`](examples/github-actions/rastray.yml) workflow that ships inline annotations, SARIF upload via `github/codeql-action/upload-sarif`, and an explicit `--fail-on high` severity gate.
- **Phase 4 — Performance analyzers** (tree-sitter ASTs)
  - Rust: `RSTR-PERF-001` (`format!` in loops, medium), `RSTR-PERF-002` (`.clone()` on iterators in `for`, low).
  - TypeScript / JavaScript / TSX: `RSTR-PERF-101` (`await` in loops, medium), `RSTR-PERF-102` (`new Date()` in loops, low).
  - Python: `RSTR-PERF-201` (string `+=` in loops, medium), `RSTR-PERF-202` (`time.sleep` in `async def`, high).
  - Go: `RSTR-PERF-301` (`defer` in for loops, medium), `RSTR-PERF-302` (`fmt.Sprintf` in loops, low).
- **Phase 3 — Dependency vulnerability analyzer**
  - Parses `Cargo.lock`, `package-lock.json`, `requirements.txt`, and `go.sum` into a generic `Package { ecosystem, name, version }`.
  - Queries [OSV.dev](https://osv.dev) `/v1/querybatch` with per-vulnerability hydration. CVSS-v3/v4 and GHSA-textual severity mapping.
  - 24-hour JSON cache at `%LOCALAPPDATA%\rastray\osv-cache.json` (Windows) / `$XDG_CACHE_HOME/rastray/` (Linux), overridable via `$RASTRAY_CACHE_DIR`.
  - `--offline` and `--no-cache` flags for air-gapped and fresh-run CI environments.
- **Phase 2 — Secret detection analyzer**
  - Eight regex patterns: AWS access key, GitHub PAT (classic + fine-grained), Slack bot token, Stripe live key, Google API key, PEM private key, npm token.
  - Shannon-entropy filter (threshold 3.0) to suppress placeholders; PEM literal bypass for the deterministic header match.
  - Lazy `OnceLock`-cached compiled patterns.
- **Phase 1 — Foundation**
  - `clap`-derive CLI, parallel `ignore::WalkBuilder` crawler with mpsc aggregator.
  - `miette`-powered human reporter; JSON reporter; `Analyzer` trait registry.
  - Documented JSON output schema (`stats` + `findings`).
  - Documented exit codes (`0` clean, `1` findings, `2` runtime error).
  - Hardened release profile (`lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`).
  - MSRV set to `1.86.0`.

### Changed

- Locked TLS stack to `rustls` (removed `native-tls` / OpenSSL surface).
- `tokio` pinned with minimal features (`rt-multi-thread`, `macros`, `net`, `io-util`, `time`, `sync`) instead of `full`.
- `thiserror` upgraded to `2.x`, `miette` to `7.6`, `tree-sitter` to `0.25`.

### Security

- Removed transitive OpenSSL dependency tree.
- Resolved RustSec advisory `RUSTSEC-2025-0023` (tokio broadcast soundness) by pinning `tokio >= 1.47`.

[Unreleased]: https://github.com/balangyaoejuspher/rastray/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.0
