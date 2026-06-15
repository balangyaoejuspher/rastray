# RSTR-CRY-006 — Python `random` / Go `math/rand` for security

## Summary

Python's stdlib `random` module and Go's `math/rand` are designed for
statistical work, not cryptography. Both are Mersenne-Twister-based
and fully predictable from a few observed outputs — fine for sampling
and simulation, fatal for token generation.

## Severity

`Medium`. Same nuance as [`RSTR-CRY-005`](./RSTR-CRY-005.md) — fires
broadly because the language has no other signal that the value will
be a token.

## Languages

Python, Go.

## What rastray flags

```python
import random
token = random.choices('abcdef0123456789', k=32)        # ← flagged
nonce = random.randint(0, 2**32)                         # ← flagged
```

```go
import "math/rand"
n := rand.Int31()                                        // ← flagged
```

## What rastray deliberately does *not* flag

- Python `secrets` module: `secrets.token_hex(16)`, `secrets.choice(seq)`.
- Go `crypto/rand`: `rand.Read(buf)`, `rand.Int(rand.Reader, max)`.

## How to fix it

Python — use `secrets`:

```python
import secrets

token = secrets.token_urlsafe(32)         # 256-bit URL-safe
pwd   = secrets.token_hex(16)             # 128-bit hex
pin   = secrets.choice(range(10**6))      # 6-digit numeric
```

Go — use `crypto/rand`:

```go
import "crypto/rand"

buf := make([]byte, 16)
if _, err := rand.Read(buf); err != nil {
    return err
}
token := hex.EncodeToString(buf)
```

For non-security purposes (a/b-testing bucket, scheduling jitter,
shuffling a deck for a non-money game) the stdlib RNGs are correct;
suppress the finding with a comment.

## References

- [Python `secrets` docs](https://docs.python.org/3/library/secrets.html)
- [Go `crypto/rand` docs](https://pkg.go.dev/crypto/rand)
- [CWE-338](https://cwe.mitre.org/data/definitions/338.html)
