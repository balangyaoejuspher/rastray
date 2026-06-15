# django-DefectDojo

[`github.com/DefectDojo/django-DefectDojo`](https://github.com/DefectDojo/django-DefectDojo) — a real Python / Django application (DefectDojo itself), not a training-vuln app. Picked specifically to show how rastray behaves on production code.

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |    1 221 |    48.3 s  |
| semgrep         |      979 |  12 m 04 s |
| gitleaks        |    1 290 |    89.2 s  |
| bandit          |      218 |    23.7 s  |
| gosec           |   *N/A*  |          — |
| eslint-security |   *N/A*  |          — |

## What rastray fires on

| code            | count | what it catches |
|-----------------|------:|------------------|
| `RSTR-PERF-201` |    634 | `string +=` inside a loop (Python) |
| `RSTR-SEC-007`  |    475 | PEM private-key blocks (overwhelmingly test fixtures) |
| `RSTR-SEC-006`  |     31 | Google API key pattern (almost entirely test/docs) |
| `RSTR-CRY-001`  |     29 | MD5 used for hashing |
| `RSTR-SEC-001`  |     26 | Hardcoded credential pattern (mostly test fixtures) |
| `RSTR-INJ-001`  |     11 | SQL injection via f-string |
| `RSTR-IAC-002`  |      4 | Docker `USER root` |
| `RSTR-CSRF-002` |      3 | Django `@csrf_exempt` |

## What 1 221 findings on a real codebase means

Most of the count is **noise typical for a fresh adoption**:

- 634 `RSTR-PERF-201` are mostly in legacy report-generation code
  where the impact is too small to warrant a refactor. Suppress
  per-file or downgrade the rule's severity in `.rastray.toml`.
- 475 `RSTR-SEC-007` are PEM blocks in `tests/fixtures/` — DefectDojo
  carries real test keys on purpose. Suppress per-folder.
- 31 `RSTR-SEC-006` are documentation examples (`AIzaSyAAAA...`) used
  in user-facing snippets. Suppress per-line.

The genuinely actionable rows are the **smaller** counts:
`RSTR-INJ-001` (11 SQL-injection candidates),
`RSTR-CRY-001` (29 MD5 sites worth checking),
`RSTR-CSRF-002` (3 `@csrf_exempt` decorators), and
`RSTR-IAC-002` (Docker running as root).

This is exactly what **baseline mode** is for:

```powershell
rastray --write-baseline rastray.baseline.json --fail-on never
# commit the baseline, then on every PR:
rastray --baseline rastray.baseline.json --fail-on high
```

After that, the 1 221 known findings stop showing up; only the
*new* ones a PR introduces fail CI.

## Headline observation

rastray is **15× faster** than Semgrep on this benchmark (48 s vs
12 min) while reporting comparable totals (1 221 vs 979). bandit
runs in 24 s but is Python-only and finds 218 issues — a useful
complement, not a replacement.

`gitleaks` reports 1 290 secret matches, vs rastray's 514
secret-family matches (`SEC-001..008`). rastray's secret coverage
is intentionally narrow; for repos where secret scanning is the
*primary* concern, run gitleaks alongside.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target django-defectdojo
```
