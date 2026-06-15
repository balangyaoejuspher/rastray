# RSTR-PERF-301 — `defer` inside a `for` loop

## Summary

Go's `defer` runs at function return, not loop iteration. A `defer`
inside a `for` body accumulates on the function's defer stack —
every iteration pushes a new entry, and nothing pops them until the
enclosing function returns. For long-running loops over file handles
or DB rows, that means resources stay held for the whole loop, not
just the iteration that opened them.

## Severity

`Medium`. Resource exhaustion (file descriptors, DB connections) is
the usual failure mode.

## Languages

Go.

## What rastray flags

```go
for _, path := range paths {
    f, err := os.Open(path)
    if err != nil { return err }
    defer f.Close()                       // ← flagged
    ...
}
```

## What rastray deliberately does *not* flag

- `defer` at function scope.
- `defer` inside an immediately-invoked closure inside the loop
  (which scopes the defer to the closure, not the function).

## How to fix it

**Option 1** — wrap the loop body in a closure (or named function)
so `defer` fires per iteration:

```go
for _, path := range paths {
    if err := func() error {
        f, err := os.Open(path)
        if err != nil { return err }
        defer f.Close()
        return process(f)
    }(); err != nil {
        return err
    }
}
```

**Option 2** — close explicitly inside the loop:

```go
for _, path := range paths {
    f, err := os.Open(path)
    if err != nil { return err }
    err = process(f)
    f.Close()
    if err != nil { return err }
}
```

The closure form is more idiomatic for clean-up that involves
multiple `defer`s (close + unlock + commit).

## References

- [Go blog: defer, panic, and recover](https://go.dev/blog/defer-panic-and-recover)
- [Effective Go: defer](https://go.dev/doc/effective_go#defer)
