# RSTR-PERF-302 — `fmt.Sprintf` inside a `for` loop

## Summary

`fmt.Sprintf` builds a fresh string per call. Inside a loop that
concatenates onto a growing buffer, the allocation churn dominates
the loop. `strings.Builder` reuses an internal byte slice and lets
`fmt.Fprintf` write directly into it.

## Severity

`Low`. Not a correctness issue; meaningful only on hot paths.

## Languages

Go.

## What rastray flags

```go
for _, x := range xs {
    out += fmt.Sprintf("%d,", x)         // ← flagged
}
```

## What rastray deliberately does *not* flag

- `fmt.Sprintf` outside loops.
- `strings.Builder` usage with `fmt.Fprintf(&b, ...)`.

## How to fix it

```go
var b strings.Builder
b.Grow(len(xs) * 4)              // optional, but often a clear win
for _, x := range xs {
    fmt.Fprintf(&b, "%d,", x)
}
out := b.String()
```

If the format is a simple separator and the elements are already
strings, `strings.Join` is even shorter:

```go
out := strings.Join(strs, ",")
```

## References

- [Go docs: `strings.Builder`](https://pkg.go.dev/strings#Builder)
- [Effective Go: Strings](https://go.dev/doc/effective_go#strings)
