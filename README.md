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

### Prerequisites

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

### From crates.io _(once published)_

```sh
cargo install rastray
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
| `--format <FMT>`         | inferred  | `human`, `json`, `gh-actions`, or `sarif`. Overrides `--json` when both are set.            |
| `-o`, `--output <FILE>`  | stdout    | Write `json` / `sarif` output to a file instead of stdout. No effect for `human`/`gh-actions`. |
| `--no-ignore`            | off       | Ignore `.gitignore`, `.ignore`, and global ignore files.                                    |
| `--hidden`               | off       | Descend into hidden files and directories.                                                  |
| `--follow-links`         | off       | Follow symlinks during the walk.                                                            |
| `-j`, `--threads <N>`    | auto      | Worker thread count for the parallel crawler.                                               |
| `--max-depth <N>`        | unlimited | Cap directory recursion depth.                                                              |
| `--config <FILE>`        | auto      | Path to a `.rastray.toml` config file. By default, rastray walks up from the scan path looking for one. |
| `--no-config`            | off       | Skip config-file discovery and loading.                                                     |
| `--fail-on <LEVEL>`      | inherited | Exit code 1 if any finding is at or above this severity. One of: `info`, `low`, `medium`, `high`, `critical`, `never`. Defaults to `--min-severity`. Overrides `[scan].fail_on` in config. |
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

The schema is considered **stable within a minor version** once Phase 2 ships.

---

## Continuous integration

A ready-to-copy GitHub Actions workflow is available under
[`examples/github-actions/`](examples/github-actions/). It runs `rastray`
on every push and pull request, posts findings as inline annotations
(`--format gh-actions`), and uploads a SARIF report to GitHub Code
Scanning (`--format sarif --output rastray.sarif`).

See [`examples/github-actions/README.md`](examples/github-actions/README.md)
for setup instructions.

---

## Security

`rastray` is itself a security-focused tool, so it holds itself to its own standards:

- No `unsafe` Rust anywhere in the codebase.
- No `unwrap` / `expect` / `panic!` in user-facing code paths.
- TLS via `rustls` only — no OpenSSL surface area.
- Minimal default feature flags on `tokio` and `reqwest` to keep the dependency graph small.
- Pinned MSRV (`1.85.0`).

To report a vulnerability, please **do not** open a public issue. See `SECURITY.md` _(coming soon)_ for the disclosure process.

---

## Contributing

Contributions are welcome. A few house rules:

- **No comments in source code.** This project deliberately ships zero comments — code must be self-documenting via clear naming. Doc-comments, inline `//` notes, and `TODO` markers will be rejected at review.
- Keep modules small and focused; one analyzer per file.
- Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before opening a PR.
- Any new dependency must be justified in the PR description against the existing dependency budget.

A fuller `CONTRIBUTING.md` will land alongside Phase 2.

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
