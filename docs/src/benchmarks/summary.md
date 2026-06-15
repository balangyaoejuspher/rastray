# Benchmarks: summary

The full sweep, all six targets × all applicable tools. See
[Methodology](./methodology.md) for what the numbers do and don't mean.

## Finding counts

| target                                                       | rastray | semgrep | gitleaks | bandit | eslint-security |
|--------------------------------------------------------------|--------:|--------:|---------:|-------:|----------------:|
| [Juice Shop](./juice-shop.md)                                |      80 |      23 |       50 |  *N/A* |          1 823† |
| [NodeGoat](./nodegoat.md)                                    |      15 |      15 |        3 |  *N/A* |           546 † |
| [DVWA](./dvwa.md)                                            |       5 |      45 |        5 |  *N/A* |          *N/A*  |
| [RailsGoat](./railsgoat.md)                                  |       6 |      22 |        1 |  *N/A* |          *N/A*  |
| [WebGoat](./webgoat.md)                                      |      17 |      21 |       23 |  *N/A* |          *N/A*  |
| [django-DefectDojo](./django-defectdojo.md)                  |   1 221 |     979 |    1 290 |    218 |          *N/A*  |

† `eslint-plugin-security`'s default ruleset is dominated by
`security/detect-object-injection` (532 of the 546 NodeGoat findings;
~95% of the Juice Shop ones too). That rule is famously noisy and
most teams disable it. The headline number overstates how many
*actionable* issues the plugin produces.

## Wall-clock (ms)

| target              | rastray | semgrep | gitleaks | bandit | eslint-security |
|---------------------|--------:|--------:|---------:|-------:|----------------:|
| Juice Shop          |   7 320 | 140 452 |   16 578 |  *N/A* |           4 570 |
| NodeGoat            |     326 |  11 275 |    1 405 |  *N/A* |           3 948 |
| DVWA                |     343 |  27 889 |    2 144 |  *N/A* |          *N/A*  |
| RailsGoat           |     419 |  27 757 |    2 627 |  *N/A* |          *N/A*  |
| WebGoat             |   1 350 | 218 546 |    7 940 |  *N/A* |          *N/A*  |
| django-DefectDojo   |  48 266 | 724 086 |   89 242 | 23 728 |          *N/A*  |

Docker-wrapped tools (semgrep, gitleaks) include the container
startup tax (~1.5–3 s per run). rastray and bandit run as native
binaries.

## Reading the comparison

A few honest observations from this data:

1. **rastray is 10–35× faster than Semgrep** at the OWASP-Top-Ten
   ruleset, on every target. The gap widens with codebase size
   (django-DefectDojo: 48 s vs 12 min).

2. **rastray and Semgrep find different things.** On DVWA, Semgrep
   reports 9× more (45 vs 5) because the `p/owasp-top-ten` registry
   contains PHP-specific data-flow templates rastray does not
   implement. On Juice Shop, rastray reports 3× more (80 vs 23) — its
   per-language regex sinks catch a lot of `fetch(req.body.x)` /
   `eval(req.body)` cases the Semgrep registry does not include.

3. **gitleaks usually finds more secrets than rastray** in real
   codebases, because it ships a 100+ pattern catalogue. rastray
   currently ships 8 secret patterns (`RSTR-SEC-001..008`). For
   pure secret-scanning, run gitleaks. rastray's secrets module is
   intentionally focused on the highest-value patterns and exists
   so that one tool can give you a complete first-line audit
   without juggling four.

4. **eslint-plugin-security inflates with `detect-object-injection`.**
   Most security teams disable that rule. Excluding it leaves ~14
   plugin-security findings on NodeGoat — comparable to rastray's
   15 and Semgrep's 15.

5. **django-DefectDojo is real-world code, not a training-vuln app.**
   The high rastray count (1 221) is dominated by `RSTR-PERF-201`
   (634 findings — `string += in a loop`) and `RSTR-SEC-007`
   (475 findings — PEM private-key blocks, mostly genuine test
   fixtures that the project carries on purpose). This is what a
   fresh adoption looks like; the
   [baseline workflow](../introduction.md) snapshots these once and
   surfaces only new findings on PRs.

## Try the harness yourself

Every column in the tables above is produced by
[`scripts/benchmarks/run.ps1`](https://github.com/balangyaoejuspher/rastray/blob/main/scripts/benchmarks/run.ps1).
Numbers will vary by machine and tool version — re-run on your own
hardware and submit a PR if you'd like to track them over time.
