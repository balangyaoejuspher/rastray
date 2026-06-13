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

The workflow runs two passes:

1. **Inline annotations** — `rastray . --format gh-actions` emits GitHub
   workflow commands so findings appear as `error` / `warning` / `notice`
   annotations on the affected lines of a pull request.
2. **SARIF upload** — `rastray . --format sarif --output rastray.sarif`
   produces a SARIF 2.1.0 document that is uploaded via
   [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action)
   so findings appear under the **Security → Code scanning** tab and gate
   merges via branch protection rules.

Both passes use `continue-on-error: true` so a finding does not fail the
build. Remove that flag once you are ready to block merges on rastray
results.

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
| Fail the build on findings            | Remove `continue-on-error: true` on the relevant step.          |
| Only report high-severity findings    | Pass `--min-severity high`.                                     |
| Skip the network (OSV vuln lookups)   | Pass `--offline`.                                               |
| Scan a subdirectory                   | Replace `.` with the path you want.                             |
| Pin to a specific rastray version     | Replace `cargo install --git …` with `cargo install rastray --version X.Y.Z` once published to crates.io. |
