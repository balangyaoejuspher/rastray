# RSTR-NET-004 — cookie `httpOnly: false` (network-rule variant)

## Summary

A cookie is set with `httpOnly: false`, exposing it to client-side
JavaScript. This is the network-layer variant of
[`RSTR-COOKIE-002`](./RSTR-COOKIE-002.md); it exists separately
because the network analyzer also catches cookie options when set on
header objects rather than via Express `res.cookie`.

## Severity

`Medium`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
const cookieOptions = { httpOnly: false };          // ← flagged
res.cookie('sid', token, cookieOptions);
```

```js
const opts = { httpOnly: false, maxAge: 3600_000 }; // ← flagged
```

## What rastray deliberately does *not* flag

- Options with `httpOnly: true`.
- Options that omit `httpOnly` entirely (caught by a higher-level
  review; this rule fires specifically on the explicit `false`).

## How to fix it

Set `httpOnly: true` (the default for the safest cookie):

```js
res.cookie('sid', token, {
    secure:    true,
    httpOnly:  true,
    sameSite:  'strict',
});
```

If the cookie genuinely must be JS-readable (CSRF mirror token,
feature-flag cookie), suppress with a comment naming the purpose:

```js
// rastray-ignore: RSTR-NET-004 — CSRF mirror cookie must be readable
res.cookie('XSRF-TOKEN', csrf, { httpOnly: false, sameSite: 'strict' });
```

## References

- [OWASP HttpOnly cookies](https://owasp.org/www-community/HttpOnly)
- [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html)
