# RSTR-JWT-005 — Go `jwt.Parse` keyfunc without method validation

## Summary

`github.com/golang-jwt/jwt`'s `Parse` / `ParseWithClaims` accepts any
signing algorithm the token *header* claims, including `none` and
HS256-vs-RS256 confusion attacks. The keyfunc you pass it must
explicitly check `token.Method` and reject anything except the algorithm
your application actually issues.

If the keyfunc returns the public key without checking — the standard
copy-paste pattern from many tutorials — an attacker can flip the
algorithm to `HS256` and forge a token signed with the *public key as
the HMAC secret*.

## Severity

`High`.

## Languages

Go.

## What rastray flags

`jwt.Parse` / `jwt.ParseWithClaims` calls whose keyfunc returns a key
without first checking `token.Method`:

```go
token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
    return publicKey, nil           // ← flagged: no t.Method check
})
```

## What rastray deliberately does *not* flag

Keyfuncs that validate the signing method first:

```go
token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return publicKey, nil
})
```

## How to fix it

Always assert the concrete `SigningMethod` type. For RS256:

```go
import "github.com/golang-jwt/jwt/v5"

func verify(raw string) (*jwt.Token, error) {
    return jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])
        }
        return publicKey, nil
    }, jwt.WithValidMethods([]string{"RS256"}))
}
```

`jwt.WithValidMethods(...)` (v5+) is a second belt-and-suspenders check
that fails earlier than the keyfunc.

## References

- [`golang-jwt` README — security considerations](https://github.com/golang-jwt/jwt/#security-considerations)
- [Auth0: critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
