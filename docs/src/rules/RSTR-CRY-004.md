# RSTR-CRY-004 — ECB cipher mode

## Summary

Electronic Codebook (ECB) encrypts every plaintext block independently
with the same key. Identical plaintext blocks therefore produce
identical ciphertext blocks — patterns in the plaintext (the famous
ECB-penguin image) are visible in the ciphertext regardless of how
strong the underlying cipher is.

ECB provides confidentiality of single blocks at best; it is never the
right mode for application data.

## Severity

`High`.

## Languages

Java, Kotlin, Python.

## What rastray flags

- Java/Kotlin: `Cipher.getInstance("AES/ECB/...")`, `Cipher.getInstance("DES/ECB/...")`, etc.
- Python: `Crypto.Util.Cipher.MODE_ECB` or `AES.new(key, AES.MODE_ECB)`.

## What rastray deliberately does *not* flag

- GCM, CCM, CBC, CTR modes.
- Stream ciphers (ChaCha20).

## How to fix it

Use AES-GCM. It provides authenticated encryption (AEAD): confidentiality
*and* integrity in one primitive, with a single per-message nonce:

```java
// Java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key,
    new GCMParameterSpec(128, nonce));
byte[] ct = cipher.doFinal(plaintext);
```

```python
# Python (cryptography)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aesgcm = AESGCM(key)
ct = aesgcm.encrypt(nonce, plaintext, aad)
```

Never reuse a (key, nonce) pair with GCM — generate the nonce from a
counter or `os.urandom(12)` per message.

## References

- [NIST SP 800-38A — Block Cipher Modes](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html)
- [The ECB-penguin image](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB))
