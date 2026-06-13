# GitHub Actions example

A drop-in workflow that runs **rastray** against your repository on every push
and pull request, surfaces findings as inline PR annotations, and uploads a
SARIF report to GitHub Code Scanning.

## Install

Copy [`rastray.yml`](rastray.yml) to `.github/workflows/rastray.yml` in your
repository:

```bash
mkdir -p .github/workflows
curl -fsSL \
  https://raw.githubusercontent.com/balangyaoejuspher/rastray/main/examples/github-actions/rastray.yml \
  -o .github/workflows/rastray.yml
```

Commit and push. The first run will install rastray with `cargo install` and
cache the resulting binary for subsequent runs.

## What it does

The workflow runs three passes:

1. **Inline annotations** — `rastray . --format gh-actions --fail-on never`
   emits GitHub workflow commands so findings appear as `error` /
   `warning` / `notice` annotations on the affected lines of a pull
   request. `--fail-on never` keeps this step non-blocking so reviewers
   always see the annotations.
2. **SARIF upload** — `rastray . --format sarif --output rastray.sarif
   --fail-on never` produces a SARIF 2.1.0 document that is uploaded via
   [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action)
   so findings appear under the **Security → Code scanning** tab. Also
   non-blocking by design.
3. **Severity gate** — `rastray . --format human --fail-on high` is the
   only blocking step. It exits `1` if any `high` or `critical` finding
   exists and gates the merge via branch protection. Adjust the level
   to taste (`medium`, `low`, etc.) or drop the step entirely for an
   advisory-only setup.

## Required permissions

```yaml
permissions:
  contents: read
  security-events: write
```

`security-events: write` is required to upload SARIF. On public
repositories this works out of the box; on private repositories it
requires GitHub Advanced Security.

## Tuning

| Want to…                              | Change                                                          |
| ------------------------------------- | --------------------------------------------------------------- |
| Block on **any** finding              | Change the gate to `--fail-on low` (or `info`).                 |
| Make the workflow purely advisory     | Remove the **Enforce severity gate** step.                      |
| Only report high-severity findings    | Pass `--min-severity high` on the annotation/SARIF passes.      |
| Skip the network (OSV vuln lookups)   | Pass `--offline`.                                               |
| Scan a subdirectory                   | Replace `.` with the path you want.                             |
| Commit per-repo policy                | Drop a `.rastray.toml` at the repo root (see [`../config/`](../config/)). |
| Pin to a specific rastray version     | Replace `cargo install --git …` with `cargo install rastray --version X.Y.Z` once published to crates.io. |
