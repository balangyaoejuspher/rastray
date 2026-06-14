# GitHub Actions example

A drop-in workflow that runs **rastray** against your repository on every push
and pull request, surfaces findings as inline PR annotations, uploads a
SARIF report to GitHub Code Scanning, and publishes a fresh SBOM on every
push to `main`.

## Install

Copy [`rastray.yml`](rastray.yml) to `.github/workflows/rastray.yml` in your
repository:

```bash
mkdir -p .github/workflows
curl -fsSL \
  https://raw.githubusercontent.com/balangyaoejuspher/rastray/main/examples/github-actions/rastray.yml \
  -o .github/workflows/rastray.yml
```

Commit and push. The first run will install rastray from the prebuilt
release via the shell installer and cache the resulting binary for
subsequent runs.

## What it does

The workflow defines two jobs:

### `scan` — static analysis (every push and PR)

Three passes against the source tree:

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

On a **pull request**, all three passes use `--since origin/<base_ref>`
to restrict analyzers to files that changed against the PR's target
branch. On a real 1,000-file monorepo this cuts PR-scan time from
~12 s to under 1 s. On pushes to `main`, the full tree is scanned.

### `sbom` — Software Bill of Materials (pushes only)

Generates two SBOMs in industry-standard formats and uploads them as
workflow artifacts so they can be consumed by Dependency-Track, Grype,
GitHub's dependency graph, etc.:

- `rastray . --format cyclonedx --output sbom.cdx.json` — CycloneDX 1.5
- `rastray . --format spdx-json --output sbom.spdx.json` — SPDX 2.3

The job runs only on pushes (and manual dispatch), not on PRs, since
the SBOM contents only change when a lockfile changes.

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
| Post a markdown summary as a PR comment | Add a step like:<br>``rastray . --format markdown --since origin/${{ github.base_ref }} -o scan.md --fail-on never``<br>then ``gh pr comment ${{ github.event.pull_request.number }} --body-file scan.md`` (needs ``pull-requests: write`` permission and ``GITHUB_TOKEN``). |
| Attach an HTML report as a CI artifact | Add ``rastray . --format html -o rastray-report.html --fail-on never`` and upload with ``actions/upload-artifact``. Reviewers download + open in any browser; no localhost or external assets. |
| Suppress legacy findings on adoption  | Run `rastray --write-baseline rastray.baseline.json --fail-on never` once, commit the file, and add `--baseline rastray.baseline.json` to each rastray call. New findings still fail the build. |
| Pin to a specific rastray version     | Set `RASTRAY_VERSION=X.Y.Z` before the installer invocation, or replace the installer with `cargo install rastray --version X.Y.Z --locked`. |

