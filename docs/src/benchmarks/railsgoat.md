# OWASP RailsGoat

[`github.com/OWASP/railsgoat`](https://github.com/OWASP/railsgoat) — Rails training app focused on mass-assignment, SQLi, and open-redirect.

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |        6 |     0.42 s |
| semgrep         |       22 |    27.8 s  |
| gitleaks        |        1 |     2.6 s  |
| bandit          |   *N/A*  |          — |
| gosec           |   *N/A*  |          — |
| eslint-security |   *N/A*  |          — |

## What rastray fires on

| code             | count | what it catches |
|------------------|------:|------------------|
| `RSTR-INJ-003`   |     2 | `eval` in Ruby |
| `RSTR-CRY-005`   |     2 | `Math.random` (in vendored JS) |
| `RSTR-REDOS-001` |     1 | Catastrophic backtracking |
| `RSTR-DES-005`   |     1 | Ruby `Marshal.load` |

## Honest observation: rastray's Ruby coverage is narrow

The current Ruby-aware rule set is:

- `RSTR-DES-005` (Marshal.load)
- `RSTR-ORM-003` (Rails create / update with raw `params`)
- `RSTR-INJ-003` (eval)

Semgrep's `p/owasp-top-ten` covers Rails-specific patterns more
broadly (`raise SQL injection in find_by_sql with interpolation`,
`HttpResponseRedirect from params`, etc.) and reports ~3× the
findings on this benchmark.

The most-cited Rails security issue — `Model.create(params[...])`
without `permit` — is what
[`RSTR-ORM-003`](../rules/RSTR-ORM-003.md) catches, but
RailsGoat itself uses the Strong-Parameters-corrected form in
most controllers, so the rule does not fire here.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target railsgoat
```
