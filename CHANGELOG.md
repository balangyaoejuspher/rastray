# Changelog

All notable changes to `rastray` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 1 foundation: `clap`-derive CLI, parallel `ignore::WalkBuilder` crawler with mpsc aggregator, `miette`-powered reporter, and `Analyzer` trait registry with `secrets` / `dependencies` / `performance` stubs.
- Documented JSON output schema (`stats` + `findings`).
- Documented exit codes (`0` clean, `1` findings, `2` runtime error).
- Hardened release profile (`lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`).
- Set MSRV to `1.86.0`.

### Changed

- Locked TLS stack to `rustls` (removed `native-tls` / OpenSSL surface).
- `tokio` pinned with minimal features (`rt-multi-thread`, `macros`, `net`, `io-util`, `time`, `sync`) instead of `full`.
- `thiserror` upgraded to `2.x`, `miette` to `7.6`, `tree-sitter` to `0.25`.

### Security

- Removed transitive OpenSSL dependency tree.
- Resolved RustSec advisory `RUSTSEC-2025-0023` (tokio broadcast soundness) by pinning `tokio >= 1.47`.

[Unreleased]: https://github.com/balangyaoejuspher/rastray/commits/main
