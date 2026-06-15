# OWASP Juice Shop

[`github.com/juice-shop/juice-shop`](https://github.com/juice-shop/juice-shop) — modern Angular + Node training app with ~80 deliberate bugs.

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |       80 |     7.3 s  |
| semgrep         |       23 |   140.5 s  |
| gitleaks        |       50 |    16.6 s  |
| eslint-security |    1 823 |     4.6 s  |
| bandit          |   *N/A*  |          — |
| gosec           |   *N/A*  |          — |

## What rastray fires on

The top families on Juice Shop:

| code            | count | what it catches |
|-----------------|------:|------------------|
| `RSTR-PERF-101` |    30 | `await` inside a loop (serialised async calls) |
| `RSTR-INJ-001`  |    12 | SQL injection via template literal |
| `RSTR-ORM-004`  |    12 | Raw SQL template literal in ORM call |
| `RSTR-CRY-005`  |    11 | `Math.random()` for security purposes |
| `RSTR-INJ-003`  |     4 | `eval` / `new Function` dynamic execution |
| `RSTR-REDOS-001`|     3 | Catastrophic backtracking heuristic |
| `RSTR-IAC-001`  |     2 | `FROM image:latest` |
| `RSTR-CRY-001`  |     2 | MD5 used for hashing |

## Where rastray catches more than Semgrep

- The 30 `RSTR-PERF-101` findings are pure throughput bugs the
  `p/owasp-top-ten` Semgrep registry does not aim for (Semgrep
  has perf packs, but they aren't in the OWASP set).
- `RSTR-CRY-005` (`Math.random()` for tokens) fires 11 times;
  Semgrep's OWASP pack does not include this generic check.
- `RSTR-ORM-004` (raw SQL template literals) fires 12 times for
  Sequelize / Knex / Prisma `.raw(\`SELECT ... ${x}\`)` patterns.

## Where Semgrep catches things rastray misses

Semgrep's deeper rules occasionally span call boundaries — for
example, identifying a sink that takes a `req`-derived value
*after* it has been assigned through a `const` (rastray
deliberately does not flow analyze; see
[Introduction](../introduction.md)).

## On the eslint-security count (1 823)

`security/detect-object-injection` produces ~95% of that total.
Most security teams disable it because it flags every
`obj[variable]` access regardless of whether `variable` is
user-controlled. Excluding it brings eslint-security's
actionable count to ~80 — comparable to what rastray reports.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target juice-shop
```
