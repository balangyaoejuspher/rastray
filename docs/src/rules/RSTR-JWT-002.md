# RSTR-JWT-002 — JWT verification disabled

## Summary

Code decodes a JWT with the signature-verification step explicitly
turned off (`verify: false` in `jsonwebtoken`, `verify_signature=False`
in `pyjwt`, `noVerify: true` etc.). The token payload is taken at face
value — anyone can mint a valid-looking JWT by base64-encoding any
JSON they like, and the application treats it as authenticated.

This defeats the entire point of JWT.

## Severity

`Critical`.

## Languages

JavaScript, TypeScript, Python.

## What rastray flags

Decode/verify calls with the verification flag disabled:

```js
jwt.verify(token, secret, { verify: false });          // ← flagged
jwt.decode(token, { verify: false });                  // ← flagged
```

```python
jwt.decode(token, options={'verify_signature': False}) # ← flagged
```

## What rastray deliberately does *not* flag

- `jwt.decode(token)` (without any options) — that decodes-without-verifying
  but is sometimes legitimate for *inspecting* a token before separately
  verifying it. Reviewers should still check those manually.
- `jwt.verify(token, secret)` with no options object — verification is
  on by default.

## How to fix it

Always verify the signature and pin the expected algorithm(s):

```js
const decoded = jwt.verify(token, PUBLIC_KEY, {
  algorithms: ['RS256'],
  issuer:    'https://issuer.example.com',
  audience:  'my-api',
});
```

```python
decoded = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=['RS256'],
    audience='my-api',
    issuer='https://issuer.example.com',
)
```

If you genuinely need the unverified header (e.g. to pick the right
key from a JWKS), use the library's documented "header-only" helper
and *still* call `verify` afterwards:

```js
const header = jwt.decode(token, { complete: true }).header;
const key    = jwks.getSigningKey(header.kid).publicKey;
const claims = jwt.verify(token, key, { algorithms: ['RS256'] });
```

## References

- [`jsonwebtoken` security considerations](https://github.com/auth0/node-jsonwebtoken#security-considerations)
- [PyJWT usage notes](https://pyjwt.readthedocs.io/en/stable/usage.html)
- [Auth0: critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
