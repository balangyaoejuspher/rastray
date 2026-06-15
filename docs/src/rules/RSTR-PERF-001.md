# RSTR-PERF-001 — Rust `format!` accumulator in a loop

## Summary

A `format!(...)` macro is invoked inside a loop and the result is
appended onto a `String` (via `push_str` or `+=`). Each iteration
allocates a fresh temporary `String`, copies it onto the accumulator,
then drops the temporary. Total allocations are *O(n)*, total bytes
copied are *O(n²)*.

## Severity

`Medium`. The wall-clock impact only shows up at loop counts in the
thousands, but the fix is a one-line refactor and turns the algorithm
from quadratic to linear.

## Languages

Rust.

## What rastray flags

```rust
let mut s = String::new();
for x in xs {
    s.push_str(&format!("{x},"));        // ← flagged
}
```

```rust
for line in lines {
    output += &format!("- {line}\n");     // ← flagged
}
```

## What rastray deliberately does *not* flag

- `format!` outside loops.
- `format!` whose result is returned, stored, or passed elsewhere
  (not accumulated).
- `write!(&mut s, "...")` — the safe replacement.

## How to fix it

Write directly into the accumulator with `write!` from `std::fmt::Write`:

```rust
use std::fmt::Write;

let mut s = String::new();
for x in xs {
    write!(&mut s, "{x},").unwrap();   // unwrap is OK; String's Write impl never fails
}
```

For known capacity, pre-allocate:

```rust
let mut s = String::with_capacity(xs.len() * 4);
```

Combined, the loop runs in linear time with at most one realloc.

## References

- [`std::fmt::Write` docs](https://doc.rust-lang.org/std/fmt/trait.Write.html)
- [Rust performance book — Strings](https://nnethercote.github.io/perf-book/strings.html)
