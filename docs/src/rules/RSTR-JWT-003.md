# RSTR-JWT-003 — hardcoded JWT secret in source

## Summary

A JWT signing call uses a literal string as the HMAC secret. As soon as
the source or compiled binary leaks (open-sourcing the repo,
leaking the artefact, a backup hitting public storage), the secret
leaks too — and anyone with the secret can mint valid tokens for any
user.

## Severity

`High`.

## Languages

JavaScript, TypeScript, Python.

## What rastray flags

`jwt.sign` (Node) / `jwt.encode` (PyJWT) calls where the second positional
argument is a string literal:

```js
const token = jwt.sign({ sub: user.id }, 'my-super-secret');   // ← flagged
```

```python
token = jwt.encode({'sub': user.id}, 'my-super-secret',
                   algorithm='HS256')                          # ← flagged
```

## What rastray deliberately does *not* flag

- Secrets read from `process.env` / `os.environ`.
- Keys loaded from disk or a secret manager.
- Public/private *key* arguments (asymmetric tokens) — those are
  long-lived material and the literal embedding is expected.

## How to fix it

Load the secret from the environment or a secret manager:

```js
const secret = process.env.JWT_SECRET;
if (!secret) throw new Error('JWT_SECRET unset');

const token = jwt.sign({ sub: user.id }, secret, {
  algorithm: 'HS256',
  expiresIn: '15m',
});
```

```python
import os
SECRET = os.environ['JWT_SECRET']

token = jwt.encode({'sub': user.id}, SECRET, algorithm='HS256')
```

For higher-stakes systems, switch to asymmetric signatures (`RS256`,
`EdDSA`) and keep the private key in a dedicated key-management service
(AWS KMS, HashiCorp Vault, GCP KMS). Verifiers only need the public key.

## How to suppress

For unit tests that need a deterministic secret, suppress per-line:

```js
// rastray-ignore: RSTR-JWT-003 — unit-test fixture secret, not production
const token = jwt.sign({ sub: 'u1' }, 'test-secret');
```

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [12-Factor Apps: Config](https://12factor.net/config)
