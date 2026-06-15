# DVWA

[`github.com/digininja/DVWA`](https://github.com/digininja/DVWA) — the classic PHP / "Damn Vulnerable Web App."

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |        5 |     0.34 s |
| semgrep         |       45 |    27.9 s  |
| gitleaks        |        5 |     2.1 s  |
| bandit          |   *N/A*  |          — |
| gosec           |   *N/A*  |          — |
| eslint-security |   *N/A*  |          — |

## What rastray fires on

| code           | count | what it catches |
|----------------|------:|------------------|
| `RSTR-INJ-003` |     5 | PHP `eval` |

## Honest observation: rastray's PHP coverage is the weakest

rastray currently ships these PHP-aware rules:

- `RSTR-INJ-003` (eval / assert with dynamic args)
- `RSTR-DES-007` (PHP `unserialize`)
- `RSTR-SEC-*` (generic secret patterns, language-agnostic)

That is much narrower than its Node / Python / Java surfaces.
Semgrep's `p/owasp-top-ten` registry has a richer PHP rule pack
and reports 45 findings against DVWA — that 9× gap is real, and
PHP-heavy projects today are better served by Semgrep until
rastray's PHP family grows.

## What's tracked

[PLAN.md Phase 11](https://github.com/balangyaoejuspher/rastray/blob/main/PLAN.md)
notes broadening PHP rules (SQLi, XSS, file upload) as a future
slice.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target dvwa
```
