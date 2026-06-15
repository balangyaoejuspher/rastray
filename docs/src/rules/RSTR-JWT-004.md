# RSTR-JWT-004 — verify without explicit algorithms list

## Summary

`jwt.verify(token, secret)` is called without an
`algorithms` argument. The library will accept whatever
algorithm the token's header field claims, which enables
the **alg-confusion attack**: an attacker takes the server's
RS256 public key, signs an HS256 token using that public
key as the HMAC secret, sets the header to `alg: HS256`,
and the library happily verifies the forgery because it
was told "any algorithm is fine".

## Severity

`High`.

## Languages

JavaScript, TypeScript, Python.

## How to fix it

Always pin the algorithm:

```js
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

```python
jwt.decode(token, key, algorithms=['RS256'])
```

For Go's `github.com/golang-jwt/jwt`, see [RSTR-JWT-005](./RSTR-JWT-005.md)
— the equivalent fix happens inside the keyfunc.

## References

- [The alg confusion attack](https://www.invicti.com/blog/web-security/jwt-algorithm-confusion-attack/)
- [PortSwigger: JWT attacks](https://portswigger.net/web-security/jwt)
