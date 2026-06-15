# RSTR-COOKIE-002 — cookie set without `httpOnly: true`

## Summary

A cookie is configured with `httpOnly: false`. Client-side JavaScript
can read the cookie via `document.cookie`, so any XSS bug — including
ones in third-party scripts loaded by the page — exfiltrates the
session token.

## Severity

`High`. Removes the most important defence-in-depth against XSS-driven
session theft.

## Languages

JavaScript, TypeScript.

## What rastray flags

Cookie option objects with `httpOnly: false`:

```js
res.cookie('sid', token, { httpOnly: false });       // ← flagged

app.use(session({
  secret: 'x',
  cookie: { httpOnly: false },                       // ← flagged
}));
```

## What rastray deliberately does *not* flag

- Cookies set with `httpOnly: true`.
- Cookies the application *needs* to read from JS (CSRF token mirror,
  feature-flag cookie). For those, name them clearly (`XSRF-TOKEN`)
  and suppress the finding with a comment.

## How to fix it

Default to `httpOnly: true` and only opt out per-cookie when the
client genuinely needs to read it. The full safe default:

```js
res.cookie('sid', token, {
  secure: true,
  httpOnly: true,
  sameSite: 'strict',
});
```

A CSRF mirror token is the canonical legitimate exception — name it
explicitly and suppress per-line:

```js
// rastray-ignore: RSTR-COOKIE-002 — CSRF mirror cookie must be JS-readable
res.cookie('XSRF-TOKEN', csrfToken, { httpOnly: false, sameSite: 'strict' });
```

## References

- [OWASP HttpOnly Cookie](https://owasp.org/www-community/HttpOnly)
- [MDN: HttpOnly cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies)
- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
