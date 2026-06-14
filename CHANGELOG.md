# Changelog

All notable changes to `rastray` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Example GitHub Actions workflow** (`examples/github-actions/`)
  now demonstrates the full Phase 8 surface: PR runs use
  `--since origin/<base_ref>` for ~24x faster incremental scans, a
  new `sbom` job uploads CycloneDX and SPDX artifacts on every push
  to `main`, and the README shows the baseline-adoption workflow.

### Added

- **Injection analyzer** (`RSTR-INJ-*`) for code-injection
  patterns: SQL built with f-strings or template literals
  (RSTR-INJ-001), `subprocess` with `shell=True` or `os.system`
  with a string arg (RSTR-INJ-002), `eval`/`exec`/`new Function`
  on user-influenced input (RSTR-INJ-003), `child_process.exec`
  with a template literal or string concatenation
  (RSTR-INJ-004), and Go `exec.Command("sh", "-c", ...)`
  (RSTR-INJ-005). Language coverage: Python, JS/TS, Go, PHP.
- **Insecure-crypto analyzer** (`RSTR-CRY-*`) for high-severity
  weak-crypto patterns: MD5/SHA-1 used for hashing, DES/3DES
  ciphers, ECB mode, `Math.random()` for tokens (JS/TS), Python
  `random` module for tokens, Go `math/rand` for tokens, Rust
  `thread_rng()` for tokens. Language coverage: Python, JS/TS,
  Java/Kotlin, Go, and Rust. Findings are reported under the new
  `security` category.
- **Java/Kotlin lockfile support** for Maven (`pom.xml` direct
  dependencies) and Gradle (`gradle.lockfile`). Maven's `pom.xml`
  parser walks `<dependencies>` blocks while skipping the
  `<dependencyManagement>` section, and skips entries whose
  `<version>` is a `${property}` reference (those require
  property resolution we don't do). Gradle's `gradle.lockfile`
  parser handles the `group:name:version=<configs>` line format
  and skips `empty=` and `#` comment lines. Both feed OSV `Maven`
  and emit `pkg:maven/<groupId>/<artifactId>@<version>` purls
  (the first `:` is rewritten to `/` for purl spec compliance).
- **Elixir lockfile support** for `mix.lock` (Hex). Walks the
  Erlang-term-formatted lockfile line-by-line, extracts the two
  quoted strings from each `{:hex, :atom, "version", ...}` tuple
  (the package name and version), and skips entries from non-hex
  sources like `{:git, ...}`. Feeds OSV `Hex` and emits
  `pkg:hex/<name>@<version>` purls.
- **Dart/Flutter lockfile support** for `pubspec.lock`. Hand-rolled
  YAML walker (matching the style of the existing `pnpm-lock.yaml`
  parser) extracts the package name and version under the
  top-level `packages:` block. Feeds OSV `Pub` and emits
  `pkg:pub/<name>@<version>` purls.
- **Swift lockfile support** for `Package.resolved` (SwiftPM).
  Handles both the v1 schema (`object.pins`) and the current v2
  schema (top-level `pins`). Package names are normalized to
  `<host>/<owner>/<repo>` (lowercased, `https://` and `.git`
  stripped, `git@host:` rewritten to `host/`) so purls follow the
  `pkg:swift/github.com/apple/swift-syntax@<version>` shape
  expected by the purl spec. Pins without a resolved version
  (branch-only refs) are skipped. Feeds OSV `SwiftURL`.
- **.NET lockfile support** for `packages.lock.json` (NuGet).
  Walks every target framework moniker (TFM) under the
  `dependencies` root and deduplicates packages shared across
  TFMs by `(name, resolved_version)`. Includes both `Direct` and
  `Transitive` dependency types. Feeds OSV `NuGet` and emits
  `pkg:nuget/<name>@<version>` purls. Note: NuGet lockfiles are
  only generated when `RestorePackagesWithLockFile` is enabled in
  the project file.
- **PHP lockfile support** for `composer.lock` (Composer). Adds
  CVE scanning against the OSV `Packagist` ecosystem and emits
  `pkg:composer/<vendor>/<name>@<version>` purls. Both the
  `packages` and `packages-dev` sections are walked. Leading `v`
  prefixes on Composer versions are stripped to match OSV's
  canonical form.
- **Ruby lockfile support** for `Gemfile.lock` (Bundler). Adds
  CVE scanning against the OSV `RubyGems` ecosystem and emits
  `pkg:gem/...` purls in CycloneDX and SPDX SBOMs. Only top-level
  resolved specs are reported; nested dependency constraints under
  each spec are intentionally skipped to avoid duplicate entries.
- **Python lockfile support** for `poetry.lock`, `Pipfile.lock`, and
  `uv.lock`. These join the existing `requirements.txt` parser, so
  Poetry, Pipenv, and uv projects now get full CVE scanning *and*
  SBOM coverage out of the box. All three feed the same `PyPI` OSV
  ecosystem and emit `pkg:pypi/...` purls.
- **SBOM output** in two industry-standard formats.
  `--format cyclonedx` emits CycloneDX 1.5 JSON; `--format spdx-json`
  emits SPDX 2.3 JSON. Both reuse the lockfile parsers rastray
  already uses for CVE detection (cargo, npm, pnpm, yarn, pip, go),
  so a single binary now covers vulnerability scanning *and* SBOM
  generation. Each package is exported with a purl identifier for
  drop-in compatibility with Dependency-Track, Grype, GitHub's
  dependency graph, etc. SBOM formats skip analyzers and run in
  roughly walk-time.
- **Incremental scanning** for fast PR CI. `--since <REF>` (e.g.
  `--since origin/main`) restricts analyzers to files changed against
  the given git ref. `--changed-only` is shorthand for `--since HEAD~1`.
  On a real 1,007-file repo, scanning a single-file PR drops from
  ~12 s (full scan) to under 1 s.
- **Baseline mode** for incremental adoption on existing codebases.
  `--write-baseline <FILE>` snapshots the current findings to a JSON
  file (deduplicated, fingerprinted by `(code, file, line, message)`).
  `--baseline <FILE>` loads that file and drops every finding whose
  fingerprint matches an entry before `--fail-on` is evaluated, so
  only **new** findings can fail the build. Verified end-to-end
  against a real project with 161 baseline findings: the second scan
  reports zero findings.

## [0.1.4] - 2026-06-14

### Fixed

- `cosign sign-blob` is now invoked twice per release archive so that
  `.sig` and `.crt` sidecars actually land in the GitHub Release
  alongside `.cosign.bundle`. cosign 2.x silently drops
  `--output-signature` and `--output-certificate` when `--bundle` is
  passed in the same call, so v0.1.3 shipped without the legacy
  sidecars that the OSSF Scorecard `Signed-Releases` check looks for.

## [0.1.3] - 2026-06-14

### Added

- Release archives now ship with **SLSA build-provenance attestations**
  produced by `actions/attest-build-provenance`. Verify with
  `gh attestation verify <archive> --repo balangyaoejuspher/rastray`.
  Satisfies the OSSF Scorecard `Provenance` check.
- Each archive's cosign keyless signature is now also emitted as
  standalone `.sig` + `.crt` sidecars alongside the existing
  `.cosign.bundle`. The `.sig` form is the file extension recognized by
  the OSSF Scorecard `Signed-Releases` check.

## [0.1.2] - 2026-06-14

### Added

- The dependency analyzer now parses **`pnpm-lock.yaml`** (both v6
  slash-prefix and v9 no-prefix entry styles) and **`yarn.lock`** (v1
  classic format and v2/v3 Berry YAML format). All extracted packages
  feed the existing OSV.dev vulnerability lookup pipeline as the `npm`
  ecosystem.

### Fixed

- OSV batch queries now chunk into groups of 1000 packages each,
  matching OSV.dev's documented per-request limit. Previously, scanning
  a project with more than 1000 lockfile entries failed with
  `400 Bad Request` and the dependency analyzer reported no findings.

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

[Unreleased]: https://github.com/balangyaoejuspher/rastray/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.4
[0.1.3]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.3
[0.1.2]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.2
[0.1.1]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.1
[0.1.0]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.0
