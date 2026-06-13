# Example .rastray.toml config files

This folder ships drop-in `.rastray.toml` snippets for common adoption
patterns. Copy the closest match to the **root of your repository**,
adjust the rule list to taste, and rastray will discover it automatically
on every scan.

## When does rastray load this file?

`rastray` walks up from the scan path looking for `.rastray.toml` in
each ancestor directory and loads the nearest one. Override the
discovery with `--config <FILE>` or skip it entirely with `--no-config`.

## Files

| File                                       | Use case                                                                 |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| [`minimal.rastray.toml`](minimal.rastray.toml)               | Starter config that documents every section but enables nothing surprising. |
| [`advisory.rastray.toml`](advisory.rastray.toml)             | "Report only" mode \u2014 emit findings but never fail the build. Good for first-week adoption. |
| [`strict.rastray.toml`](strict.rastray.toml)                 | Block merges on any `medium`+ finding, ignore generated paths, no rule downgrades. |
| [`monorepo.rastray.toml`](monorepo.rastray.toml)             | Suitable for large monorepos: aggressive ignore globs for build artifacts, vendored code, and language-specific caches. |

## Schema reference

```toml
[scan]
fail_on = "high"            # "info" | "low" | "medium" | "high" | "critical" | "never"

[scan.ignore]
paths = ["target/**", "dist/**", "vendor/**"]

[rules]
"RSTR-SEC-005" = false                       # disable a rule
"RSTR-PERF-001" = { severity = "low" }       # downgrade a rule
"RSTR-PERF-002" = { enabled = false }        # explicit disable
```

## Inline suppressions

For one-off false positives that don't deserve a config entry, use an
inline directive in the source file itself:

```rust
// rastray-ignore: RSTR-PERF-001
for i in 0..1000 { let _ = format!("{i}"); }
```

```python
result += item  # rastray-ignore-line: RSTR-PERF-201
```

```go
// rastray-ignore-file: RSTR-PERF-301
```

Three forms are supported:

| Form                       | Scope                |
| -------------------------- | -------------------- |
| `rastray-ignore`           | next line            |
| `rastray-ignore-line`      | same line            |
| `rastray-ignore-file`      | the entire file      |

All forms accept a comma-separated list of codes (e.g. `RSTR-PERF-001,
RSTR-SEC-002`) and the wildcard `*` ("any code").
