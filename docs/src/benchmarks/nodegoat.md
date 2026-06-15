# OWASP NodeGoat

[`github.com/OWASP/NodeGoat`](https://github.com/OWASP/NodeGoat) — small Express training app with a clean mapping to OWASP Top 10.

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |       15 |     0.33 s |
| semgrep         |       15 |    11.3 s  |
| gitleaks        |        3 |     1.4 s  |
| eslint-security |      546 |     3.9 s  |
| bandit          |   *N/A*  |          — |
| gosec           |   *N/A*  |          — |

## What rastray fires on

| code              | count | what it catches |
|-------------------|------:|------------------|
| `RSTR-CRY-005`    |     7 | `Math.random()` for security |
| `RSTR-INJ-003`    |     4 | `eval` / `new Function` |
| `RSTR-NOSQLI-002` |     2 | Mongo `$where` with request input |
| `RSTR-REDOS-001`  |     1 | Catastrophic backtracking |
| `RSTR-RDR-001`    |     1 | Express `res.redirect(req.x)` |

## Headline observation

rastray and Semgrep report **the same number of findings (15)** on
NodeGoat, but rastray runs **34× faster** (0.33 s vs 11.3 s, both
on the same hardware). The rule mix differs slightly — rastray
catches more `Math.random()` / `eval` cases, Semgrep catches a few
more interprocedural cases that need a small amount of flow.

## On the eslint-security count (546)

532 of the 546 are `security/detect-object-injection`. The other
14 are genuine — they cover roughly the same surface as rastray's
15 and Semgrep's 15. Most teams disable
`detect-object-injection` for exactly this reason; once that's
done, the three tools are comparable on this benchmark.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target nodegoat
```
