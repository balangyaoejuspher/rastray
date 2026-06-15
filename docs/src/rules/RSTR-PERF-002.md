# RSTR-PERF-002 — Rust `for x in xs.clone()`

## Summary

A `for` loop iterates over `xs.clone()` (or `xs.to_vec()`, etc.).
The clone walks the entire collection and allocates a new owned copy
just for the iteration — wasted memory and wasted CPU. Borrowing
`&xs` does the same job with zero allocations.

The clone is usually copy-paste from "I needed to satisfy the borrow
checker once, then never revisited" or "the IDE auto-suggested
`.clone()`."

## Severity

`Low`. Correctness-neutral; the impact is purely overhead.

## Languages

Rust.

## What rastray flags

```rust
for item in items.clone() {      // ← flagged
    process(item);
}

for row in rows.to_vec() {       // ← flagged
    print(row);
}
```

## What rastray deliberately does *not* flag

- `for item in &items` / `for item in items.iter()` — borrowing.
- `for item in items` where `items: Vec<T>` and the loop consumes
  `items` (moves) — the original cannot be used after the loop.
- Clones followed by mutation: `let mut copy = xs.clone(); copy.push(...)`
  — clone is doing real work.

## How to fix it

Borrow:

```rust
for item in &items {            // borrows; iteration over &T
    process(item);
}
```

If you need to consume the value but also keep the collection,
clone *inside* the loop body for the specific elements that need it:

```rust
for item in &items {
    consumer.give(item.clone());   // clone only the elements consumer needs to own
}
```

## References

- [Rust performance book — Clone](https://nnethercote.github.io/perf-book/general-tips.html)
- [Clippy lint: `redundant_clone`](https://rust-lang.github.io/rust-clippy/master/index.html#redundant_clone)
