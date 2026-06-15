# OWASP RailsGoat

[`github.com/OWASP/railsgoat`](https://github.com/OWASP/railsgoat) — Rails training app focused on mass-assignment, SQLi, and open-redirect.

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |       11 |     2.0 s  |
| semgrep         |       22 |    27.8 s  |
| gitleaks        |        1 |     2.6 s  |
| bandit          |   *N/A*  |          — |
| gosec           |   *N/A*  |          — |
| eslint-security |   *N/A*  |          — |

## What rastray fires on

| code             | count | what it catches |
|------------------|------:|------------------|
| `RSTR-INJ-009`   |     3 | `params[...].constantize` / `.classify` — mobile_controller, benefit_forms |
| `RSTR-INJ-003`   |     2 | `eval` |
| `RSTR-CRY-005`   |     2 | `Math.random` (vendored JS) |
| `RSTR-INJ-008`   |     1 | `User.where("id = '#{params[:user][:id]}'")` — users_controller |
| `RSTR-ORM-005`   |     1 | `params.require(:user).permit!` — users_controller |
| `RSTR-REDOS-001` |     1 | Catastrophic backtracking |
| `RSTR-DES-005`   |     1 | Ruby `Marshal.load` |

## What changed in v0.11.0

Rastray's Rails coverage grew from 6 findings to 11 on RailsGoat
between v0.10.0 and v0.11.0 — almost doubling the catch rate on this
target. The new rules added in this release:

- [`RSTR-INJ-008`](../rules/RSTR-INJ-008.md) — Rails `.where` with
  string interpolation of `params`. Fires on
  `users_controller.rb:29`: `User.where("id = '#{params[:user][:id]}'")`.
- [`RSTR-INJ-009`](../rules/RSTR-INJ-009.md) — `params[...].constantize`
  / `.classify` / `.safe_constantize`. Fires on the mobile-API
  pattern of "deserialise whatever class the client names."
- [`RSTR-INJ-010`](../rules/RSTR-INJ-010.md) — `render inline:` /
  `text:` with `#{params[...]}` interpolation (SSTI).
- [`RSTR-ORM-005`](../rules/RSTR-ORM-005.md) — `params.require(:x).permit!`
  open-permit. Fires on `users_controller.rb:50`.
- [`RSTR-RDR-004`](../rules/RSTR-RDR-004.md) — `redirect_to params[...]`
  open-redirect. Does not fire on RailsGoat because the sample uses
  the indirect form `path = params[:url]; redirect_to path` — same
  one-step taint scope the rest of rastray uses.

The remaining gap vs Semgrep is mostly the same "indirect flow"
pattern as on DVWA: RailsGoat consistently assigns `params[...]` to
a local first, then uses the local. Semgrep's rule pack tracks that
single assignment; rastray deliberately does not. For codebases that
match rastray's direct-sink scope, the new rules close most of the
real-world gap.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target railsgoat
```
