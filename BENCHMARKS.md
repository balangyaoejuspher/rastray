# Benchmarks

rastray is benchmarked against five other free / open-source static analyzers across six known-vulnerable applications.

The full comparison — methodology, per-target breakdowns, and honest commentary on where rastray catches more, where it catches less, and how fast it runs — lives on the documentation site:

→ **<https://balangyaoejuspher.github.io/rastray/benchmarks/summary.html>**

## Quick summary

| target            | rastray | semgrep | gitleaks | bandit | eslint-security |
|-------------------|--------:|--------:|---------:|-------:|----------------:|
| Juice Shop        |      80 |      23 |       50 |  *N/A* |          1 823† |
| NodeGoat          |      15 |      15 |        3 |  *N/A* |           546 † |
| DVWA              |       5 |      45 |        5 |  *N/A* |          *N/A*  |
| RailsGoat         |      11 |      22 |        1 |  *N/A* |          *N/A*  |
| WebGoat           |      17 |      21 |       23 |  *N/A* |          *N/A*  |
| django-DefectDojo |   1 221 |     979 |    1 290 |    218 |          *N/A*  |

† `eslint-plugin-security`'s default ruleset is dominated by `security/detect-object-injection`, which most teams disable. Excluding it brings actionable counts down to roughly the same range as rastray and Semgrep.

| target            | rastray | semgrep | gitleaks | bandit | eslint-security |
|-------------------|--------:|--------:|---------:|-------:|----------------:|
| Juice Shop        |   7.3 s | 140.5 s |   16.6 s |  *N/A* |           4.6 s |
| NodeGoat          |  0.33 s |  11.3 s |    1.4 s |  *N/A* |           3.9 s |
| DVWA              |  0.34 s |  27.9 s |    2.1 s |  *N/A* |          *N/A*  |
| RailsGoat         |   2.0 s |  27.8 s |    2.6 s |  *N/A* |          *N/A*  |
| WebGoat           |   1.4 s | 218.5 s |    7.9 s |  *N/A* |          *N/A*  |
| django-DefectDojo |  48.3 s | 12 m 04 s |  89.2 s | 23.7 s |          *N/A*  |

rastray runs **10×-156× faster than Semgrep** on the OWASP-Top-Ten ruleset across every target.

## Reproduce

Every number above is produced by [`scripts/benchmarks/run.ps1`](scripts/benchmarks/run.ps1). See the [methodology page](https://balangyaoejuspher.github.io/rastray/benchmarks/methodology.html) for the full set of clone / install / run commands.
