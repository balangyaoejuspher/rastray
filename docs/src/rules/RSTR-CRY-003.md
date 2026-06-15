# RSTR-CRY-003 — DES / 3DES cipher

## Summary

DES (1977) and 3DES (1998) are both deprecated. DES has a 56-bit key —
brute-forceable in hours on modern hardware — and 3DES is vulnerable
to the **Sweet32** birthday attack against its 64-bit block size. NIST
disallowed 3DES for new applications in 2017 and removed all uses by
the end of 2023.

## Severity

`High`.

## Languages

Java, Kotlin, Python, Go.

## What rastray flags

- Java/Kotlin: `Cipher.getInstance("DES/...")` or `Cipher.getInstance("DESede/...")` / `"TripleDES/..."`.
- Python: `from Crypto.Cipher import DES, DES3` (PyCryptodome / PyCrypto).
- Go: `crypto/des` import or `des.NewCipher(...)` / `des.NewTripleDESCipher(...)`.

## What rastray deliberately does *not* flag

- AES-anything (the modern default).
- ChaCha20-Poly1305.

## How to fix it

Switch to AES-GCM (or ChaCha20-Poly1305 if AES-NI is unavailable):

```java
// Java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

```python
# Python (cryptography)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aesgcm = AESGCM(key)             # 16/24/32-byte key
ct = aesgcm.encrypt(nonce, plaintext, aad)
```

```go
// Go
import "crypto/aes"; import "crypto/cipher"

block, _ := aes.NewCipher(key)
gcm, _   := cipher.NewGCM(block)
ct       := gcm.Seal(nil, nonce, plaintext, aad)
```

## References

- [NIST SP 800-67 Rev. 2 — disallowed status](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf)
- [Sweet32 birthday attack](https://sweet32.info/)
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html)
