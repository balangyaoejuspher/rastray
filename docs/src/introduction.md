# rastray rules

This site documents every rule code that
[rastray](https://github.com/balangyaoejuspher/rastray)
can emit. Each page describes:

- what the bug class is,
- a true-positive example (the shape we flag),
- one or two false-positive examples (the shape we
  deliberately don't flag),
- the canonical remediation,
- references to OWASP / CWE / language-specific docs.

## How rules are numbered

Every finding has a stable code of the form
``RSTR-<FAMILY>-<NNN>``. The family prefix tells you which
analyzer module fired the rule, and the numeric suffix is
stable across releases — once a rule code ships, it never
gets renumbered, even if the underlying detection logic is
refined.

## What rastray is, and isn't

rastray is a **fast, deterministic, free** static-analysis
CLI written in Rust. It scans a project tree in parallel and
runs a registry of analyzers against it. It is **not** a
taint-analysis engine — every rule on this site requires the
user-controlled value to appear *directly* in the sink call.
For multi-step dataflow analysis, reach for
[CodeQL](https://codeql.github.com/) or
[Semgrep Pro](https://semgrep.dev/products/semgrep-code/).

## Installation

```sh
# Prebuilt installer (recommended)
curl -fsSL https://github.com/balangyaoejuspher/rastray/releases/latest/download/install.sh | sh

# Or from crates.io (requires Rust toolchain)
cargo install rastray --locked
```

## License

Apache-2.0 OR MIT (same as the rastray repo).
