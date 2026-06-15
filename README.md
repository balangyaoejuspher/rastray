# rastray

[![Crates.io](https://img.shields.io/crates/v/rastray.svg?logo=rust)](https://crates.io/crates/rastray)
[![Downloads](https://img.shields.io/crates/d/rastray.svg)](https://crates.io/crates/rastray)
[![CI](https://github.com/balangyaoejuspher/rastray/actions/workflows/ci.yml/badge.svg)](https://github.com/balangyaoejuspher/rastray/actions/workflows/ci.yml)
[![Security audit](https://github.com/balangyaoejuspher/rastray/actions/workflows/audit.yml/badge.svg)](https://github.com/balangyaoejuspher/rastray/actions/workflows/audit.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/balangyaoejuspher/rastray/badge)](https://securityscorecards.dev/viewer/?uri=github.com/balangyaoejuspher/rastray)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.86.0-blue.svg)](Cargo.toml)

> Blazing-fast static analysis CLI for security, dependency, and performance audits.

`rastray` is a single-binary, Rust-native command-line scanner that walks a project tree in parallel and runs a registry of pluggable analyzers against it — looking for hard-coded secrets, vulnerable or out-of-date dependencies, common OWASP-top-10 bug shapes (SSRF, XSS, open-redirect, SSTI, XXE, NoSQL injection, path traversal, command injection, broken crypto, GHA / IaC misconfig, unsafe deserialization, plaintext network endpoints), and hot-path performance smells. It is designed to be **fast enough to run in pre-commit hooks** and **strict enough to gate CI pipelines**.

It is **not** another lint wrapper. `rastray` carries its own crawler, its own diagnostic renderer (powered by [`miette`](https://crates.io/crates/miette)), and emits human, JSON, SARIF, GitHub Actions, Markdown, HTML, CycloneDX, and SPDX output from the same engine.

### What rastray is, and what it isn't

`rastray` runs **deterministic pattern checks** — three tiers:

1. **Regex sinks** (most security rules) — fast linear-time pattern matching with no lookarounds.
2. **Lockfile vulnerability scans** (`RSTR-DEP-*`) — parse `Cargo.lock`, `package-lock.json`, `requirements.txt`, etc. and cross-reference against the [OSV.dev](https://osv.dev) advisory database.
3. **Tree-sitter AST queries** (most performance rules) — structural matches against parsed source trees.

It **deliberately does not** do multi-step taint flow analysis. Every security rule requires the user-controlled value to appear **directly** in the sink call (e.g. `fetch(req.body.url)` is flagged; `const u = req.body.url; fetch(u);` is not). That's what [CodeQL](https://codeql.github.com/) and [Semgrep](https://semgrep.dev/) do across function boundaries. CodeQL is free for open-source projects (paid via GitHub Advanced Security for closed-source); Semgrep ships a free OSS engine plus a paid Pro tier for deeper interprocedural rules. `rastray` catches the common 80% where the dangerous value is right there in the call, with no AI, no inference, and no false-positive guesswork. For the remaining 20%, reach for one of those tools.

No LLM. No telemetry. No network access at scan time (OSV lookups are opt-in and cacheable). One binary. Free.

---

## Why rastray?

Most security/dep/perf tools in the polyglot world fall into one of three buckets:

1. **Language-locked** (`bandit` for Python, `npm audit` for Node, `cargo audit` for Rust). You end up running four of them in CI.
2. **Heavy SaaS** (Snyk, SonarQube). Paid, network-dependent, slow.
3. **Generic linters with plugins**. Good signal, but configuration sprawl.

`rastray` aims to be the **fourth option**: one offline binary, one config-free invocation, polyglot from day one, and aggressively fast because it is built on `ignore::WalkBuilder` (the engine that powers `ripgrep`) plus a `tokio` runtime for network-bound advisory lookups.

See [`BENCHMARKS.md`](BENCHMARKS.md) for a side-by-side comparison against Semgrep, bandit, gosec, gitleaks, and eslint-plugin-security on six known-vulnerable codebases. rastray runs 10×–156× faster than Semgrep at OWASP-Top-Ten coverage on every target tested.

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

> The prebuilt installer is the recommended path because the
> downloaded binary is statically linked — **no Rust toolchain, no C
> compiler, no system dependencies required**. The other install
> options below all compile from source and need the prerequisites
> listed.

### Prerequisites _(only required for source builds — including `cargo install`)_

- **Rust** 1.86.0 or newer (`rustup default stable`)
- A working C/C++ toolchain for linking:
  - Windows → **Visual Studio Build Tools** with the _Desktop development with C++_ workload (provides `link.exe`)
  - macOS → Xcode Command Line Tools (`xcode-select --install`)
  - Linux → `build-essential` / `gcc` + `pkg-config`

### Homebrew (macOS / Linux)

A Homebrew formula is provided at
[`dist/homebrew/rastray.rb`](dist/homebrew/rastray.rb). It downloads
the same checksum-verified release tarball the shell installer uses,
so no Rust toolchain is required.

A dedicated tap repository will be published soon; until then,
install directly from the formula file in this repo:

```sh
brew install --formula https://raw.githubusercontent.com/balangyaoejuspher/rastray/main/dist/homebrew/rastray.rb
```

### Scoop (Windows)

A Scoop manifest is provided at
[`dist/scoop/rastray.json`](dist/scoop/rastray.json). Same approach:
downloads the release zip, verifies SHA256, drops `rastray.exe` on
your `PATH`.

A dedicated bucket repository will be published soon; until then,
install directly from the manifest in this repo:

```powershell
scoop install https://raw.githubusercontent.com/balangyaoejuspher/rastray/main/dist/scoop/rastray.json
```

### From crates.io

```sh
cargo install rastray --locked
```

> `cargo install` compiles `rastray` from source on your machine, so
> the [Prerequisites](#prerequisites-only-required-for-source-builds--including-cargo-install)
> above apply. If you don't already have the Rust toolchain and a C
> linker installed, prefer the prebuilt-binary installer above.

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

| Flag                      | Default   | Description                                                                                                                                                                                                                                        |
| ------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PATH`                    | `.`       | Directory or file to scan.                                                                                                                                                                                                                         |
| `--min-severity <LEVEL>`  | `low`     | Suppress findings below this severity. One of: `info`, `low`, `medium`, `high`, `critical`.                                                                                                                                                        |
| `--min-confidence <LEVEL>` | `low`    | Suppress findings below this confidence. One of: `low`, `medium`, `high`. Every built-in rule defaults to `high`; rules that opt into a lower value (typically heuristic detectors) can be filtered out with `--min-confidence high`.              |
| `--json`                  | off       | Shortcut for `--format json`.                                                                                                                                                                                                                      |
| `--format <FMT>`          | inferred  | `human`, `json`, `gh-actions`, `sarif`, `markdown`, `html`, `cyclonedx`, or `spdx-json`. Overrides `--json` when both are set. `html` requires `-o`. `cyclonedx` and `spdx-json` emit an SBOM and skip analyzers.                                  |
| `-o`, `--output <FILE>`   | stdout    | Write `json` / `sarif` / `markdown` / `html` / SBOM output to a file instead of stdout. Required for `html`. No effect for `human` / `gh-actions`.                                                                                                 |
| `--no-ignore`             | off       | Ignore `.gitignore`, `.ignore`, and global ignore files.                                                                                                                                                                                           |
| `--hidden`                | off       | Descend into hidden files and directories.                                                                                                                                                                                                         |
| `--follow-links`          | off       | Follow symlinks during the walk.                                                                                                                                                                                                                   |
| `--include-minified`      | off       | Scan minified files (`*.min.js`, `*.bundle.css`, etc.) that are skipped by default. Detection uses both name patterns and an average-line-length probe over the first 8 KB.                                                                        |
| `-j`, `--threads <N>`     | auto      | Worker thread count for the parallel crawler.                                                                                                                                                                                                      |
| `--max-depth <N>`         | unlimited | Cap directory recursion depth.                                                                                                                                                                                                                     |
| `--config <FILE>`         | auto      | Path to a `.rastray.toml` config file. By default, rastray walks up from the scan path looking for one.                                                                                                                                            |
| `--no-config`             | off       | Skip config-file discovery and loading.                                                                                                                                                                                                            |
| `--no-default-skip`       | off       | Disable the built-in "skip likely-fixture noise" filter. By default, rastray drops findings for a small set of rules when they appear inside common test-fixture directories (`tests/`, `unittests/`, `__tests__/`, `fixtures/`, `samples/`, etc.) — currently `RSTR-SEC-006` and `RSTR-SEC-007`, which routinely fire on intentional sample keys / API keys in test data. Pass this flag to get every finding regardless of path. |
| `--fail-on <LEVEL>`       | inherited | Exit code 1 if any finding is at or above this severity. One of: `info`, `low`, `medium`, `high`, `critical`, `never`. Defaults to `--min-severity`. Overrides `[scan].fail_on` in config.                                                         |
| `--baseline <FILE>`       | off       | Load a baseline JSON file; findings whose fingerprint matches an entry are dropped before `--fail-on` is evaluated. Lets teams adopt rastray on a legacy codebase without rewriting every existing issue.                                          |
| `--write-baseline <FILE>` | off       | Write the current findings to a baseline file (after config + suppression filters, before `--min-severity`). Use this once to snapshot known findings, then commit the file.                                                                       |
| `--since <REF>`           | off       | Restrict analyzers to files changed vs the given git ref (e.g. `origin/main`, `HEAD~1`). Massive speedup on PR CI.                                                                                                                                 |
| `--changed-only`          | off       | Shorthand for `--since HEAD~1`. Useful in commit hooks.                                                                                                                                                                                            |
| `--fix`                   | off       | Preview safe auto-fixes (unified diff per finding) for the rules that have a 1:1 mechanical remediation (currently `RSTR-DES-002`, `RSTR-CRY-001`, `RSTR-CRY-002`). Does not modify files. Combine with `--yes` to write the changes back to disk. |
| `--yes`                   | off       | With `--fix`: actually apply the previewed substitutions. No effect without `--fix`.                                                                                                                                                               |
| `-v`, `--verbose`         | off       | Repeat for more detail (`-v`, `-vv`, `-vvv`).                                                                                                                                                                                                      |
| `-q`, `--quiet`           | off       | Suppress non-finding output. Mutually exclusive with `--verbose`.                                                                                                                                                                                  |

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

[[custom_rule]]
id          = "ACME-001"
pattern     = '\bTODO\(security\)\b'
message     = "security TODO marker found"
severity    = "medium"
help        = "resolve the TODO before merging"
extensions  = ["rs", "py"]
```

#### Custom rules

`[[custom_rule]]` blocks let teams ship project-specific regex checks
without touching the rastray source. Each entry must provide an `id`, a
`pattern` (Rust regex), and a human-readable `message`. Optional fields:

- `severity` — `info`, `low`, `medium` (default), `high`, or `critical`.
- `help` — remediation hint shown alongside the finding.
- `extensions` — restrict the rule to files with these extensions
  (e.g. `["rs", "py"]`). Omit to scan every source/config file.

Findings emitted by custom rules participate in baseline diffing,
suppression, severity remapping, autofix exclusion, and CI gating
exactly like built-in rules.

### Baseline mode

Adopting rastray on an existing codebase that already has dozens or
hundreds of findings? Snapshot them once as a **baseline**, commit the
file, and let PR CI gate only on _new_ findings:

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

### Auto-fix

For a curated set of rules with a 1:1 mechanical remediation,
`rastray --fix` can preview and apply the safe substitution
automatically. Dry-run first (prints a unified diff per
finding, modifies nothing):

```sh
rastray --fix
```

Then, once you've reviewed the diff:

```sh
rastray --fix --yes
```

The current fixer set is deliberately small — only the
rules where a single-line string replacement is
unambiguously correct:

| Rule | Substitution | Languages |
|---|---|---|
| `RSTR-DES-002` | `yaml.load(` → `yaml.safe_load(` | Python |
| `RSTR-CRY-001` | MD5 hash construction → SHA-256 | Python, Node, Java, Go |
| `RSTR-CRY-002` | SHA-1 hash construction → SHA-256 | Python, Node, Java, Go |

Rules that need multi-line refactoring (`verify=False`
removal, `Math.random()` token generation, GHA SHA pinning)
are not auto-fixed — they require parsing the surrounding
call to keep argument lists and identifiers correct.
Free / deterministic / no-LLM means we will not guess.

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
(`requirements.txt` + `poetry.lock` + `Pipfile.lock` + `uv.lock`),
`gem` (`Gemfile.lock`), `composer` (`composer.lock`), `nuget`
(`packages.lock.json`), `swift` (`Package.resolved`), `pub`
(`pubspec.lock`), `hex` (`mix.lock`), `maven` (`pom.xml` direct
deps + `gradle.lockfile`), and `golang` (`go.sum`). Each package is
exported with a [purl](https://github.com/package-url/purl-spec)
identifier so the SBOM round-trips into Dependency-Track, Grype,
GitHub's dependency graph, etc.

### Visual reports

For sharing scan results outside the terminal, rastray emits two
human-friendly formats. Both are **single self-contained files** —
no localhost server, no CDN, no network at view time.

```sh
# Single-file HTML report — open in any browser (file://). Includes
# an SVG severity donut, category bar chart, search box, severity
# chips, and a sortable findings table. Respects prefers-color-scheme
# for light/dark; collapses to stacked cards at <720 px.
rastray . --format html -o report.html
start report.html        # Windows  (open / xdg-open on macOS / Linux)

# Markdown summary — paste straight into a GitHub PR comment. Top of
# report is a Severity + Category table; per-severity finding tables
# are wrapped in <details open> blocks with sensible caps (all
# Critical, top 10 High, top 5 Medium, top 5 Low).
rastray . --format markdown -o scan.md
gh pr comment 123 --body-file scan.md
```

The HTML report is one self-contained file, so it works equally well
as a `gh release` asset, a CI artifact (`actions/upload-artifact`),
or an email attachment. The recipient just opens it — no install.

### Exit codes

`rastray` follows the standard CI-friendly convention:

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| `0`  | Scan completed; **no findings** at or above the fail-on threshold.          |
| `1`  | Scan completed; **at least one finding** at or above the fail-on threshold. |
| `2`  | **Runtime error** (I/O failure, malformed input, configuration error).      |

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
                  ┌─────▼──────────────────────────────────────────┐
                  │  modules/                                      │
                  │    Security:  secrets, crypto, injection,      │
                  │               network, gha, iac,               │
                  │               deserialization, path_traversal, │
                  │               ssrf, xss, open_redirect,        │
                  │               ssti, xxe, nosqli                │
                  │    Deps:      dependencies (OSV.dev)           │
                  │    Perf:      performance (tree-sitter)        │
                  └─────┬──────────────────────────────────────────┘
                        │ Vec<Finding>
                  ┌─────▼──────┐
                  │ reporter.rs│   human | json | sarif | markdown |
                  │            │   html  | gh-actions | cyclonedx |
                  │            │   spdx-json
                  └────────────┘
```

- **`main.rs`** — orchestrator. Installs the `miette` hook, parses CLI, runs the crawler, dispatches analyzers, applies severity filtering, renders, returns `ExitCode`.
- **`cli.rs`** — `clap` derive structs (`Cli`, `Severity`, `OutputFormat`). Handles `--json` / `--format` reconciliation.
- **`crawler.rs`** — parallel filesystem walk. Hard-blocks noise dirs (`.git`, `node_modules`, `target`, `dist`, `build`, `.venv`, `venv`, `__pycache__`) and minified files (`*.min.js`, `*.bundle.css`, plus any JS/TS/CSS whose first 8 KB averages over 500 chars per line). Classifies each remaining entry as `Manifest | Source | Config | Other`.
- **`reporter.rs`** — `Finding`, `Location`, `Report`. Multi-format renderer: `miette::Diagnostic` for humans, plus JSON, SARIF, Markdown, HTML, GitHub Actions annotations, CycloneDX SBOM, and SPDX SBOM. Source spans are read lazily and degrade gracefully on I/O errors.
- **`modules/`** — `Analyzer` trait + registry. Three tiers: regex sinks (most security rules), lockfile parsing + OSV.dev (`RSTR-DEP-*`), and tree-sitter AST queries (most `RSTR-PERF-*`). New analyzers implement `Analyzer` and are appended to `default_registry()`.

### Rule families

Every finding has a stable `RSTR-<FAMILY>-<NNN>` code. Use these in
`.rastray.toml` to disable or re-tune individual rules. The
per-rule reference site at
[balangyaoejuspher.github.io/rastray](https://balangyaoejuspher.github.io/rastray/)
has a dedicated page for each rule code with examples, the
canonical remediation, and CWE / OWASP references.

| Family          | Module            | What it catches                                                                                                                                                                                                                                                                                                     |
| --------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RSTR-SEC-*`    | `secrets`         | High-entropy hard-coded credentials, AWS / GitHub / Stripe / OpenAI token patterns.                                                                                                                                                                                                                                 |
| `RSTR-CRY-*`    | `crypto`          | Broken algorithms (`md5`, `sha1`, DES, ECB mode), weak RNG (`Math.random`, `random.random` for security).                                                                                                                                                                                                           |
| `RSTR-INJ-*`    | `injection`       | SQL injection via f-strings / template literals, `shell=True` in `subprocess`, `eval(user_input)`, `sh -c <user_cmd>`.                                                                                                                                                                                              |
| `RSTR-NET-*`    | `network`         | Plaintext `http://` endpoints in code, disabled TLS verification (`verify=False`, `rejectUnauthorized: false`).                                                                                                                                                                                                     |
| `RSTR-GHA-*`    | `gha`             | GitHub Actions misconfig: unpinned actions, missing `permissions:`, write tokens.                                                                                                                                                                                                                                   |
| `RSTR-IAC-*`    | `iac`             | Terraform / Dockerfile / k8s misconfig (root user, `:latest`, public S3 buckets, missing limits).                                                                                                                                                                                                                   |
| `RSTR-DES-*`    | `deserialization` | `pickle.loads(user_input)`, `yaml.load` without `SafeLoader`, Java `ObjectInputStream` on untrusted data.                                                                                                                                                                                                           |
| `RSTR-PTH-*`    | `path_traversal`  | `open(user_input)` / `fs.readFile(req.body.path)` without normalization.                                                                                                                                                                                                                                            |
| `RSTR-SSRF-*`   | `ssrf`            | `fetch(req.body.url)`, `requests.get(request.args.get('u'))`, `http.Get(r.FormValue(...))`.                                                                                                                                                                                                                         |
| `RSTR-XSS-*`    | `xss`             | Reflected XSS (Express, Flask, Go `fmt.Fprintf`) and DOM XSS (`innerHTML = location.hash`).                                                                                                                                                                                                                         |
| `RSTR-RDR-*`    | `open_redirect`   | `res.redirect(req.query.next)`, Flask / Django `redirect(request.args.get(...))`.                                                                                                                                                                                                                                   |
| `RSTR-SSTI-*`   | `ssti`            | `render_template_string(req.body)`, `pug.render(req.body)`, `Handlebars.compile(req.body)`.                                                                                                                                                                                                                         |
| `RSTR-XXE-*`    | `xxe`             | Python stdlib `xml.etree`, `lxml.etree.XMLParser(resolve_entities=True)`, Java `DocumentBuilderFactory` without hardening, `libxmljs.parseXml(..., {noent: true})`.                                                                                                                                                 |
| `RSTR-NOSQLI-*` | `nosqli`          | MongoDB operator injection (`users.find({ user: req.body.user })`), Mongo `$where` with request input (Critical — RCE in the database process).                                                                                                                                                                     |
| `RSTR-DEP-*`    | `dependencies`    | Known-vulnerable packages in `Cargo.lock`, `package-lock.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`, `Package.resolved`, `pubspec.lock`, `mix.lock`, Gradle / Maven, `go.sum`. Cross-referenced against [OSV.dev](https://osv.dev). |
| `RSTR-PERF-*`   | `performance`     | Tree-sitter AST checks: `String += in loop`, redundant `Vec::clone`, allocations inside hot loops.                                                                                                                                                                                                                  |

Every security finding follows the **captured-call-site message
convention**: the matched call is interpolated into the message body so
200 findings in a report produce 200 distinguishable lines, not 200
copies of the same warning. Help text embeds the idiomatic remediation
snippet per language and framework (e.g. `defusedxml` for Python XXE,
`html.EscapeString` for Go XSS, `String(req.body.user)` coercion for
Mongo).

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

### Pre-commit framework

`rastray` ships a top-level [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml)
so any project using [pre-commit](https://pre-commit.com) can wire it in
with one entry. Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/balangyaoejuspher/rastray
    rev: v0.11.0
    hooks:
      - id: rastray
```

Then install the framework and the hook:

```sh
pip install pre-commit
pre-commit install
```

Two hook IDs are exposed:

| Hook ID          | Behaviour                                                                                                |
| ---------------- | -------------------------------------------------------------------------------------------------------- |
| `rastray`        | Runs `rastray --fail-on high`. Blocks the commit only on High or Critical findings. Recommended default. |
| `rastray-strict` | Runs `rastray --fail-on low`. Blocks the commit on any finding at Low severity or above.                 |

Both hooks use `language: system`, which means `rastray` must already be
on your `PATH`. Install it via the [prebuilt installer](#prebuilt-binaries-recommended)
or `cargo install rastray --locked` first. The hooks deliberately do not
build `rastray` from source on every contributor's machine — that would
turn a one-second pre-commit check into a multi-minute Rust compile.

### Git-history secret sweep

For audit and incident-response cases ("did we ever commit a key?"),
`rastray` can walk the full git commit history and run the secrets
analyzer against every file blob that any commit ever added or
modified:

```sh
rastray secrets --history             # walk the entire history
rastray secrets --history --since v0.10.0
rastray secrets --history --max-commits 500
```

The scanner shells out to `git log` / `git diff-tree` / `git show`,
so it works on any repository where `git` is on `PATH` — no
additional dependency. Findings render with a synthetic location
like `path/to/file.env@abcdef1` so reviewers can `git show
abcdef1:path/to/file.env` directly to inspect the historical blob.

Findings honour the same `--min-severity` / `--min-confidence` /
`--json` / `--format` flags as a working-tree scan. The exit code is
`0` if zero secrets surfaced and `1` otherwise (no `--fail-on`
threshold for the subcommand — any historical leak is treated as a
finding worth flagging).

### Container image scanning

`rastray` can also scan container image archives on disk for the
same set of secret patterns:

```sh
docker save my-app:1.0 -o my-app.tar
rastray image my-app.tar
```

The scanner accepts a `docker save` tarball or an OCI image layout
exported to a tarball. It walks every layer inside the archive,
recursively unpacks nested `.tar` / `.tar.gz` / `.tgz` entries up
to four levels deep, and runs the secrets analyzer against every
text file inside. Binary files and files larger than
`--max-file-bytes` (default 4 MiB) are skipped.

Findings render with a synthetic location like
`my-app.tar::sha256.../layer.tar::etc/leaked.env` so reviewers can
tell exactly which layer the leak lives in.

**Scope notes:**

- This is **not** a CVE scanner for OS packages — it does not parse
  `dpkg`/`rpm`/`apk` databases or query a vulnerability DB. For
  full OS-package CVE coverage, run `trivy image` alongside; the
  two tools cover non-overlapping concerns (rastray = secrets and
  IaC misconfig baked into images, trivy = known-CVE OS / language
  packages).
- The scanner reads from disk only — no registry pulls, no docker
  daemon required. Use `docker save` (or `skopeo copy
  docker://image dir:./image`) to materialise the archive first.

### Editor integration (LSP)

`rastray` ships a built-in Language Server Protocol implementation so
findings surface inline in any LSP-aware editor (VS Code, Neovim,
Helix, Zed, Emacs) as you save a file — no waiting for CI or
pre-commit.

```sh
rastray lsp
```

This speaks LSP over stdio. Each `textDocument/didOpen` and
`textDocument/didSave` triggers an in-process scan of that single file
through the existing analyzer registry, and emits one
`textDocument/publishDiagnostics` notification per file. Each
diagnostic carries:

- `severity` mapped from rastray (`Critical`/`High` → Error, `Medium`
  → Warning, `Low` → Information, `Info` → Hint).
- `code` set to the `RSTR-<FAMILY>-<NNN>` rule id.
- `source` set to `"rastray"`.
- `message` carrying the captured-call-site text.
- `relatedInformation` carrying the per-language remediation help
  text.

Wire it up per editor:

**Neovim (with `nvim-lspconfig`)**

```lua
require("lspconfig.configs").rastray = {
  default_config = {
    cmd = { "rastray", "lsp" },
    filetypes = { "rust", "python", "javascript", "typescript", "go", "java" },
    root_dir = require("lspconfig.util").find_git_ancestor,
    single_file_support = true,
  },
}
require("lspconfig").rastray.setup({})
```

**Helix (`languages.toml`)**

```toml
[language-server.rastray]
command = "rastray"
args = ["lsp"]

[[language]]
name = "python"
language-servers = [{ name = "rastray", except-features = ["format"] }]
```

**VS Code** — install the bundled extension from
[`editors/vscode/`](editors/vscode/). Until a marketplace
publish lands, sideload the `.vsix` built locally with
`cd editors/vscode && npm install && npm run package`
(installs to `editors/vscode/rastray-*.vsix`, then
"Install from VSIX..." in the Extensions view). The
extension is a thin client around `rastray lsp`;
activation languages and the path to the `rastray` binary
are configurable via the `rastray.*` settings.

The LSP runs in offline mode (no OSV.dev network calls), uses a single
worker thread, and only scans the single file that just opened/saved
— not the whole workspace. This keeps latency under 100 ms on typical
files.

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
