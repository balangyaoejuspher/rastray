# WebGoat

[`github.com/WebGoat/WebGoat`](https://github.com/WebGoat/WebGoat) — large Spring-based Java training app.

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |       17 |     1.4 s  |
| semgrep         |       21 |   218.5 s  |
| gitleaks        |       23 |     7.9 s  |
| bandit          |   *N/A*  |          — |
| gosec           |   *N/A*  |          — |
| eslint-security |   *N/A*  |          — |

## What rastray fires on

| code           | count | what it catches |
|----------------|------:|------------------|
| `RSTR-PERF-102`|     8 | `new Date()` inside a loop (in WebGoat's bundled JS) |
| `RSTR-DES-006` |     4 | Java `ObjectInputStream.readObject` |
| `RSTR-SEC-007` |     2 | PEM private-key block |
| `RSTR-INJ-003` |     1 | `eval` (JSP / inline scriptlets) |
| `RSTR-XXE-005` |     1 | XML factory without entity hardening |
| `RSTR-CRY-001` |     1 | MD5 used for hashing |

## Headline observation

rastray and Semgrep land in the same ballpark (17 vs 21), but
**rastray finishes in 1.4 s while Semgrep takes 3 m 38 s — a
156× speedup**. WebGoat is the largest repository tested and
the gap is biggest here; rastray's regex + targeted Tree-sitter
strategy scales with file count, while Semgrep's
dataflow engine pays a per-file cost that adds up on a 20 MB tree.

The four `RSTR-DES-006` findings are exactly the
[`ObjectInputStream` RCE class](../rules/RSTR-DES-006.md) WebGoat
teaches in its `Deserialization` chapter — they map cleanly to the
lesson, not false positives.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target webgoat
```
