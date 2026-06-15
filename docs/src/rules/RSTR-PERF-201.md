# RSTR-PERF-201 — Python `s += '...'` inside a loop

## Summary

Python strings are immutable. `s += chunk` inside a loop creates a
fresh string of length `|s| + |chunk|` each iteration, so the loop
is `O(n²)` in the total output length.

CPython has an opportunistic optimisation that *sometimes* mutates
the string in place when the reference count is 1, but it's
implementation-specific and disappears the moment another reference
takes a peek (logging, debugger, intermediate assignment). The
explicit-list-and-`join` form is reliably linear.

## Severity

`Medium`.

## Languages

Python.

## What rastray flags

```python
out = ''
for line in lines:
    out += line + '\n'                   # ← flagged
```

## What rastray deliberately does *not* flag

- `out = '\n'.join(lines)`.
- Numeric `+=`.
- Concat outside loops.

## How to fix it

Collect into a list and join once:

```python
parts = []
for line in lines:
    parts.append(line + '\n')
out = ''.join(parts)
```

Or use an `io.StringIO` for explicit incremental writes:

```python
import io

buf = io.StringIO()
for line in lines:
    buf.write(line)
    buf.write('\n')
out = buf.getvalue()
```

Both forms are `O(n)`.

## References

- [Python performance tips — concat](https://wiki.python.org/moin/PythonSpeed/PerformanceTips#String_Concatenation)
