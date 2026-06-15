# RSTR-JWT-001 — alg:none or wildcard algorithms accepted

## Summary

The JWT verifier accepts `algorithms: ['none']` or
`algorithms: ['*']`. The `none` algorithm is the special
JWT value meaning "no signature, trust the payload"; the
`*` wildcard means "accept whatever algorithm the token's
header claims". Both let an attacker forge a token with any
identity by manipulating the JWT header.

## Severity

`Critical`.

## Languages

JavaScript, TypeScript, Python.

## How to fix it

Always pass an explicit algorithm list matching what you
signed the token with:

```js
jwt.verify(token, secret, { algorithms: ['HS256'] });   // ← good
```

```python
jwt.decode(token, key, algorithms=['RS256'])            # ← good
```

If you're using asymmetric keys (`RS256`, `ES256`) pin to
that specific algorithm. **Never** include `'none'` in the
list, and never include `'*'`.

## References

- [CVE-2015-9235: JWT alg=none bypass](https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-c2qf-rxjj-qqgw)
- [Auth0: JWT handbook (alg confusion section)](https://auth0.com/resources/ebooks/jwt-handbook)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
