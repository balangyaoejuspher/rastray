# RSTR-CRY-007 — Rust `rand::thread_rng()` for security

## Summary

The `rand` crate's `thread_rng()` returns the per-thread default RNG.
As of `rand 0.7+` it is seeded from the OS CSPRNG, but the *output
stream* is not specified to be cryptographically secure across crate
versions, and historically the type behind `thread_rng()` has changed.
For tokens, keys, nonces, and any other security-sensitive use, always
use `OsRng` (or `getrandom` directly) so the guarantee is explicit and
stable across `rand` releases.

## Severity

`Medium`.

## Languages

Rust.

## What rastray flags

```rust
use rand::Rng;

let token: u64 = rand::thread_rng().gen();       // ← flagged
```

## What rastray deliberately does *not* flag

- `rand::rngs::OsRng`.
- `getrandom::getrandom(&mut buf)`.
- `ring::rand::SystemRandom::new()`.

## How to fix it

```rust
use rand::rngs::OsRng;
use rand::RngCore;

let mut buf = [0u8; 32];
OsRng.fill_bytes(&mut buf);
```

Or with `getrandom` directly (zero deps):

```rust
let mut buf = [0u8; 32];
getrandom::getrandom(&mut buf).expect("entropy unavailable");
```

For UUIDs:

```rust
use uuid::Uuid;
let id = Uuid::new_v4();      // backed by getrandom
```

## References

- [`rand` book: CSPRNG considerations](https://rust-random.github.io/book/guide-rngs.html#cryptographically-secure-rngs)
- [`getrandom` crate](https://docs.rs/getrandom/)
- [CWE-338](https://cwe.mitre.org/data/definitions/338.html)
