# RSTR-CRY-001 — MD5 used for hashing

## Summary

MD5 is **cryptographically broken**: practical collision
attacks have been published since 2004, and chosen-prefix
collisions since 2007. Any use of MD5 for a security
purpose (digital signatures, password hashing, token
generation, integrity verification of untrusted data) is a
real vulnerability.

## Severity

`High`.

## Languages

Python, JavaScript, TypeScript, Java, Kotlin, Go, Rust.

## What rastray flags

The MD5 constructor in any supported language:

- Python: `hashlib.md5(...)`
- Node: `crypto.createHash('md5')` / `crypto.createHash("md5")`
- Java: `MessageDigest.getInstance("MD5")`
- Go: `md5.New()` (after importing `crypto/md5`)

## What rastray deliberately does *not* flag

Non-security MD5 use cases:
- Cache-busting hashes (file fingerprints in build output)
- Bloom-filter / consistent-hashing data structures
- Legacy protocols where the spec mandates MD5 (e.g. some
  RADIUS attribute hashing)

The rule fires anyway in these cases — suppress per-line
with `// rastray-ignore: RSTR-CRY-001` and a comment
explaining the non-security context.

## How to fix it

Replace MD5 with SHA-256 (or SHA-3-256). The constructor
names are uniform:

| Language | MD5 (bad) | SHA-256 (good) |
|---|---|---|
| Python | `hashlib.md5(data)` | `hashlib.sha256(data)` |
| Node | `crypto.createHash('md5')` | `crypto.createHash('sha256')` |
| Java | `MessageDigest.getInstance("MD5")` | `MessageDigest.getInstance("SHA-256")` |
| Go | `md5.New()` | `sha256.New()` (import `crypto/sha256`) |

`rastray --fix --yes` auto-applies these substitutions.

For **password hashing specifically**, do not switch to
SHA-256 either — use `argon2id` (or `bcrypt` if Argon2 is
unavailable).

## References

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [NIST: MD5 deprecation](https://csrc.nist.gov/projects/hash-functions)
- [Wang et al. 2004 MD5 collision paper](https://eprint.iacr.org/2004/199)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
