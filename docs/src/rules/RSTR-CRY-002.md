# RSTR-CRY-002 — SHA-1 used for hashing

## Summary

SHA-1 is broken: the [SHAttered attack (2017)](https://shattered.io/)
produced the first practical collision, and modern attacks
can produce chosen-prefix collisions for under USD 50,000.
SHA-1 is unsuitable for any new security use.

## Severity

`High`.

## Languages

Python, JavaScript, TypeScript, Java, Kotlin, Go, Rust.

## What rastray flags

- Python: `hashlib.sha1(...)`
- Node: `crypto.createHash('sha1')` / `crypto.createHash("sha1")`
- Java: `MessageDigest.getInstance("SHA-1")` and `"SHA1"`
- Go: `sha1.New()` (after importing `crypto/sha1`)

## How to fix it

Replace with SHA-256. `rastray --fix --yes` auto-applies the
substitution across all four languages.

For **HMAC** specifically, `HMAC-SHA1` is still considered
safe for *integrity* because HMAC's security doesn't reduce
to the underlying hash's collision resistance — but new
code should use `HMAC-SHA256` anyway because there's no
reason to prefer the broken hash.

## References

- [SHAttered: the first SHA-1 collision](https://shattered.io/)
- [NIST: SP 800-131A retirement of SHA-1](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
