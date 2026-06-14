# rastray

[![CI](https://github.com/balangyaoejuspher/rastray/actions/workflows/ci.yml/badge.svg)](https://github.com/balangyaoejuspher/rastray/actions/workflows/ci.yml)
[![Security audit](https://github.com/balangyaoejuspher/rastray/actions/workflows/audit.yml/badge.svg)](https://github.com/balangyaoejuspher/rastray/actions/workflows/audit.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/balangyaoejuspher/rastray/badge)](https://securityscorecards.dev/viewer/?uri=github.com/balangyaoejuspher/rastray)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.86.0-blue.svg)](Cargo.toml)

> Blazing-fast static analysis CLI for security, dependency, and performance audits.

`rastray` is a single-binary, Rust-native command-line scanner that walks a project tree in parallel and runs a registry of pluggable analyzers against it — looking for hard-coded secrets, vulnerable or out-of-date dependencies, and hot-path performance smells. It is designed to be **fast enough to run in pre-commit hooks** and **strict enough to gate CI pipelines**.

It is **not** another lint wrapper. `rastray` carries its own crawler, its own diagnostic renderer (powered by [`miette`](https://crates.io/crates/miette)), and emits both human-friendly terminal output and machine-readable JSON from the same engine.

---

## Why rastray?

Most security/dep/perf tools in the polyglot world fall into one of three buckets:

1. **Language-locked** (`bandit` for Python, `npm audit` for Node, `cargo audit` for Rust). You end up running four of them in CI.
2. **Heavy SaaS** (Snyk, SonarQube). Paid, network-dependent, slow.
3. **Generic linters with plugins**. Good signal, but configuration sprawl.

`rastray` aims to be the **fourth option**: one offline binary, one config-free invocation, polyglot from day one, and aggressively fast because it is built on `ignore::WalkBuilder` (the engine that powers `ripgrep`) plus a `tokio` runtime for network-bound advisory lookups.

---

## Installation

### Prebuilt binaries _(recommended)_

Each release attaches statically-linked binaries for the common
platforms. The shell installer downloads, checksum-verifies, and
extracts the right archive for your OS / arch:

**Linux / macOS**

```sh
curl -fsSL https://github.com/balangyaoejuspher/rastray/releases/latest/download/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://github.com/balangyaoejuspher/rastray/releases/latest/download/install.ps1 | iex
```

Both installers honor `RASTRAY_VERSION` (e.g. `0.1.0`) and
`RASTRAY_INSTALL_DIR`. See [`install/README.md`](install/README.md) for
details.

### From crates.io

```sh
cargo install rastray --locked
```

### Prerequisites _(for source builds)_

- **Rust** 1.86.0 or newer (`rustup default stable`)
- A working C/C++ toolchain for linking:
  - Windows → **Visual Studio Build Tools** with the _Desktop development with C++_ workload (provides `link.exe`)
  - macOS → Xcode Command Line Tools (`xcode-select --install`)
  - Linux → `build-essential` / `gcc` + `pkg-config`

### From source

```sh
git clone https://github.com/balangyaoejuspher/rastray.git
cd rastray
cargo build --release
# Binary lands at ./target/release/rastray
```

---

## Usage

```sh
rastray [OPTIONS] [PATH]
```

`PATH` defaults to the current directory.

### Common invocations

```sh
# Scan the current project, human-friendly output
rastray

# Scan a specific directory, only show medium+ findings
rastray ./services/api --min-severity medium

# Emit JSON for CI ingestion
rastray --json > rastray-report.json

# Force inclusion of hidden files and ignored paths
rastray --hidden --no-ignore

# Limit parallelism (default is num_cpus)
rastray -j 4

# Crank verbosity for debugging the crawler
rastray -vv
```

### Flags

| Flag                     | Default   | Description                                                                                 |
| ------------------------ | --------- | ------------------------------------------------------------------------------------------- |
| `PATH`                   | `.`       | Directory or file to scan.                                                                  |
| `--min-severity <LEVEL>` | `low`     | Suppress findings below this severity. One of: `info`, `low`, `medium`, `high`, `critical`. |
| `--json`                 | off       | Shortcut for `--format json`.                                                               |
| `--format <FMT>`         | inferred  | `human`, `json`, `gh-actions`, `sarif`, `cyclonedx`, or `spdx-json`. Overrides `--json` when both are set. `cyclonedx` and `spdx-json` emit an SBOM and skip analyzers. |
| `-o`, `--output <FILE>`  | stdout    | Write `json` / `sarif` output to a file instead of stdout. No effect for `human`/`gh-actions`. |
| `--no-ignore`            | off       | Ignore `.gitignore`, `.ignore`, and global ignore files.                                    |
| `--hidden`               | off       | Descend into hidden files and directories.                                                  |
| `--follow-links`         | off       | Follow symlinks during the walk.                                                            |
| `-j`, `--threads <N>`    | auto      | Worker thread count for the parallel crawler.                                               |
| `--max-depth <N>`        | unlimited | Cap directory recursion depth.                                                              |
| `--config <FILE>`        | auto      | Path to a `.rastray.toml` config file. By default, rastray walks up from the scan path looking for one. |
| `--no-config`            | off       | Skip config-file discovery and loading.                                                     |
| `--fail-on <LEVEL>`      | inherited | Exit code 1 if any finding is at or above this severity. One of: `info`, `low`, `medium`, `high`, `critical`, `never`. Defaults to `--min-severity`. Overrides `[scan].fail_on` in config. |
| `--baseline <FILE>`      | off       | Load a baseline JSON file; findings whose fingerprint matches an entry are dropped before `--fail-on` is evaluated. Lets teams adopt rastray on a legacy codebase without rewriting every existing issue. |
| `--write-baseline <FILE>`| off       | Write the current findings to a baseline file (after config + suppression filters, before `--min-severity`). Use this once to snapshot known findings, then commit the file. |
| `--since <REF>`          | off       | Restrict analyzers to files changed vs the given git ref (e.g. `origin/main`, `HEAD~1`). Massive speedup on PR CI. |
| `--changed-only`         | off       | Shorthand for `--since HEAD~1`. Useful in commit hooks. |
| `-v`, `--verbose`        | off       | Repeat for more detail (`-v`, `-vv`, `-vvv`).                                               |
| `-q`, `--quiet`          | off       | Suppress non-finding output. Mutually exclusive with `--verbose`.                           |

### Configuration file

If a `.rastray.toml` file exists in the scan directory (or any ancestor),
rastray loads it automatically. Use `--config` to point at a specific file
or `--no-config` to skip loading entirely.

```toml
[scan]
fail_on = "high"            # exit non-zero only on findings >= high (default: any)

[scan.ignore]
paths = ["target/**", "dist/**", "vendor/**"]

[rules]
"RSTR-SEC-005" = false                          # disable a rule entirely
"RSTR-PERF-001" = { severity = "low" }          # downgrade a rule's severity
"RSTR-PERF-002" = { enabled = false }           # explicit form
```

### Baseline mode

Adopting rastray on an existing codebase that already has dozens or
hundreds of findings? Snapshot them once as a **baseline**, commit the
file, and let PR CI gate only on *new* findings:

```sh
# One-time: snapshot known findings as a baseline
rastray --write-baseline rastray.baseline.json --fail-on never
git add rastray.baseline.json && git commit -m "chore: rastray baseline"

# On every PR: only NEW findings fail the build
rastray --baseline rastray.baseline.json --fail-on high
```

Baseline entries are matched on `(rule code, normalised file path, line
number, message)` — cosmetic changes like severity downgrades or rule
renumbering don't drift, but adding a new occurrence or moving an issue
to a new line surfaces as a new finding.

### Incremental scanning

On a large monorepo, scanning every file on every PR is wasteful.
`--since <REF>` restricts analyzers to files changed against the given
git ref:

```sh
# In PR CI
rastray --since origin/main --fail-on high

# In a commit hook (shorthand for --since HEAD~1)
rastray --changed-only --fail-on high
```

Both flags only run the **analyzers** on changed files — the file walker
still discovers everything (cheap) but tree-sitter and OSV only see the
diff. Typical PR speedup: a 1000-file repo that takes ~12 s for a full
scan drops to under 1 s when only one source file changed.

Requires `git` on `PATH` and the scan path to be inside a git
repository.

### SBOM output

Emit a Software Bill of Materials directly from the same lockfiles
rastray already parses for CVE detection — no second tool needed:

```sh
# CycloneDX 1.5 JSON
rastray --format cyclonedx -o sbom.cdx.json

# SPDX 2.3 JSON
rastray --format spdx-json  -o sbom.spdx.json
```

SBOM formats skip analyzers and emit only package metadata, so they
finish in roughly the same time as the filesystem walk. Supported
ecosystems: `cargo`, `npm` (npm + pnpm + yarn lockfiles), `pypi`
(`requirements.txt`), and `golang` (`go.sum`). Each package is
exported with a [purl](https://github.com/package-url/purl-spec)
identifier so the SBOM round-trips into Dependency-Track, Grype,
GitHub's dependency graph, etc.

### Exit codes

`rastray` follows the standard CI-friendly convention:

| Code | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| `0`  | Scan completed; **no findings** at or above the fail-on threshold.     |
| `1`  | Scan completed; **at least one finding** at or above the fail-on threshold. |
| `2`  | **Runtime error** (I/O failure, malformed input, configuration error). |

The fail-on threshold defaults to `--min-severity` and can be overridden
via `--fail-on <LEVEL>` or `[scan].fail_on` in `.rastray.toml`. Use
`--fail-on never` (or `fail_on = "never"`) to always exit `0` regardless
of findings — useful for advisory CI runs.

Wire it into CI as:

```sh
rastray --min-severity high || exit $?
```

---

## Architecture

```
                  ┌────────────┐
                  │   cli.rs   │   clap-derive parser
                  └─────┬──────┘
                        │ Cli
                  ┌─────▼──────┐
                  │ crawler.rs │   ignore::WalkBuilder + mpsc aggregator
                  └─────┬──────┘
                        │ CrawlSummary
                  ┌─────▼──────┐
                  │  modules/  │   Analyzer trait registry
                  │  secrets   │
                  │  deps      │
                  │  perf      │
                  └─────┬──────┘
                        │ Vec<Finding>
                  ┌─────▼──────┐
                  │ reporter.rs│   Human (miette) | JSON (serde)
                  └────────────┘
```

- **`main.rs`** — orchestrator. Installs the `miette` hook, parses CLI, runs the crawler, dispatches analyzers, applies severity filtering, renders, returns `ExitCode`.
- **`cli.rs`** — `clap` derive structs (`Cli`, `Severity`, `OutputFormat`). Handles `--json` / `--format` reconciliation.
- **`crawler.rs`** — parallel filesystem walk. Hard-blocks noise dirs (`.git`, `node_modules`, `target`, `dist`, `build`, `.venv`, `venv`, `__pycache__`). Classifies each entry as `Manifest | Source | Config | Other`.
- **`reporter.rs`** — `Finding`, `Location`, `Report`. Dual renderer: `miette::Diagnostic` for humans, `serde_json::to_string_pretty` for machines. Source spans are read lazily and degrade gracefully on I/O errors.
- **`modules/`** — analyzer trait + registry. New analyzers implement `Analyzer` and are appended to `default_registry()`.

### Adding a new analyzer

1. Create `src/modules/<name>.rs`.
2. Define a unit struct and implement `Analyzer`:
   ```rust
   pub struct MyAnalyzer;
   impl MyAnalyzer { pub fn new() -> Self { Self } }
   impl Analyzer for MyAnalyzer {
       fn name(&self) -> &'static str { "my-analyzer" }
       fn analyze(&self, crawl: &CrawlSummary) -> Result<Vec<Finding>, AnalyzerError> {
           Ok(Vec::new())
       }
   }
   ```
3. Register it in `default_registry()` in `src/modules/mod.rs`.

---

## JSON output schema

```jsonc
{
  "stats": {
    "files_scanned": 0,
    "manifests": 0,
    "source_files": 0,
    "config_files": 0,
    "other_files": 0,
    "crawl_errors": 0,
    "skipped": 0,
  },
  "perf": {
    "walk_ms": 0,
    "analyze_ms": 0,
    "total_ms": 0,
    "bytes_scanned": 0,
  },
  "findings": [
    {
      "code": "RSTR-XXX-000",
      "message": "...",
      "severity": "low|medium|high|critical|info",
      "category": "secret|dependency|performance|crawler|internal",
      "help": "remediation hint or null",
      "location": {
        "file": "relative/path/to/file",
        "line": 0,
        "column": 0,
        "byte_offset": 0,
        "byte_length": 0,
      },
    },
  ],
}
```

The JSON output is considered **stable within a minor version** and follows semantic versioning. See [`CHANGELOG.md`](CHANGELOG.md) for any schema additions.

---

## Continuous integration

A ready-to-copy GitHub Actions workflow is available under
[`examples/github-actions/`](examples/github-actions/). It runs `rastray`
on every push and pull request, posts findings as inline annotations
(`--format gh-actions`), and uploads a SARIF report to GitHub Code
Scanning (`--format sarif --output rastray.sarif`).

See [`examples/github-actions/README.md`](examples/github-actions/README.md)
for setup instructions.

Drop-in `.rastray.toml` snippets for common adoption patterns (advisory,
strict, monorepo) are in [`examples/config/`](examples/config/).

---

## Security

`rastray` is itself a security-focused tool, so it holds itself to its own standards:

- No `unsafe` Rust anywhere in the codebase.
- No `unwrap` / `expect` / `panic!` in user-facing code paths.
- TLS via `rustls` only — no OpenSSL surface area.
- Minimal default feature flags on `tokio` and `reqwest` to keep the dependency graph small.
- Pinned MSRV (`1.86.0`).

To report a vulnerability, please **do not** open a public issue. See [`SECURITY.md`](SECURITY.md) for the disclosure process.

---

## Contributing

`rastray` is currently source-available but **closed to external code contributions**
while the architecture stabilises. Bug reports, security reports, feature requests,
and forks are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full policy
and the rules that apply to pre-approved pull requests.

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
