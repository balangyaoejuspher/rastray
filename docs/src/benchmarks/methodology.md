# Benchmarks: methodology

This chapter compares rastray to five other free / open-source static
analyzers across six known-vulnerable applications. The goal is not to
declare a winner — each tool has a different scope — but to show
honestly **what rastray catches, what it misses, and how fast it
runs** against named codebases the reader can reproduce.

## Reproducibility

Every number on these pages comes from
[`scripts/benchmarks/run.ps1`](https://github.com/balangyaoejuspher/rastray/blob/main/scripts/benchmarks/run.ps1)
in this repository. Run it yourself:

```powershell
# one-time: clone the targets
mkdir bench-workdir\targets
cd bench-workdir\targets
git clone --depth 1 https://github.com/juice-shop/juice-shop.git
git clone --depth 1 https://github.com/OWASP/NodeGoat.git nodegoat
git clone --depth 1 https://github.com/digininja/DVWA.git dvwa
git clone --depth 1 https://github.com/OWASP/railsgoat.git
git clone --depth 1 https://github.com/WebGoat/WebGoat.git webgoat
git clone --depth 1 https://github.com/DefectDojo/django-DefectDojo.git django-defectdojo

# tools (one-time): docker pull images, install bandit
docker pull returntocorp/semgrep:latest
docker pull securego/gosec:latest
docker pull zricethezav/gitleaks:latest
pip install bandit

# build rastray release binary
cargo build --release

# run the full sweep
powershell -File scripts/benchmarks/run.ps1
```

The harness writes per-tool JSON outputs to `bench-workdir/results/<target>/`
and a consolidated `summary.json` with finding counts and wall-clock
timings.

## Targets

| target                                                          | language(s)             | scope                                              |
|-----------------------------------------------------------------|--------------------------|----------------------------------------------------|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)    | TypeScript / JavaScript  | Modern Angular + Node app; ~80 deliberate bugs.    |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat)             | JavaScript (Express)     | Smaller; clean OWASP Top 10 mapping.               |
| [DVWA](https://github.com/digininja/DVWA)                       | PHP                      | The classic PHP training app.                      |
| [OWASP RailsGoat](https://github.com/OWASP/railsgoat)           | Ruby (Rails)             | Rails-specific mass-assignment, SQLi, redirect.    |
| [WebGoat](https://github.com/WebGoat/WebGoat)                   | Java (Spring)            | Large Java codebase; broad rule surface.           |
| [django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Python (Django)      | Real-world application (not training-vuln) used to show how rastray behaves on a production codebase. |

## Tools

| tool                                                            | language coverage              | version pinned for this run |
|-----------------------------------------------------------------|--------------------------------|------------------------------|
| **rastray**                                                     | polyglot (security + perf)     | 0.8.0                        |
| [Semgrep CE](https://github.com/semgrep/semgrep)                | polyglot (the `p/owasp-top-ten` registry)  | 1.165.0          |
| [bandit](https://github.com/PyCQA/bandit)                       | Python                         | 1.9.4                        |
| [gosec](https://github.com/securego/gosec)                      | Go                             | dev / 2026-02-28             |
| [gitleaks](https://github.com/gitleaks/gitleaks)                | secret patterns (filesystem)   | v8.30.1                      |
| [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) | JS / TS  | eslint 10 + plugin-security 4 |

`gosec` is Go-only and therefore does not run against any of the
chosen targets, so its row is omitted from the tables. The harness
correctly flags it as **N/A** for non-Go targets.

## What the numbers mean

- **findings** — the raw count of issues reported by each tool, with
  its default ruleset (or `p/owasp-top-ten` for Semgrep). The counts
  are **not directly comparable**: tools use different severities,
  group identical issues differently, and have wildly different scopes
  (rastray flags 19 analyzer families, gitleaks is secrets-only, etc.).

- **wall-clock (ms)** — measured from process launch to completion on
  the same Windows 11 host running Docker Desktop. Docker-wrapped
  tools (semgrep, gosec, gitleaks) include the container startup tax
  (~1.5–3 s per run). Treat the comparison as
  *order-of-magnitude*, not *millisecond-precise*.

- **0 / blank** — tool is applicable but found nothing, or tool is
  not applicable (e.g. bandit on a Ruby codebase).

For honest comparison, read the per-target page for each app —
those discuss *which* rules each tool fires on, where rastray
catches things others miss, and where rastray misses things others
catch.
