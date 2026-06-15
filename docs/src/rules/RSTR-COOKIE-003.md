# RSTR-COOKIE-003 — `sameSite: 'none'` cookie

## Summary

A cookie is configured with `sameSite: 'none'`. Browsers will send
this cookie on every cross-site request, which means the cookie is
attached to requests originating from third-party pages — the exact
condition that CSRF exploits.

Two failure modes:

1. **Without `secure: true`** — modern browsers reject the combination
   outright; the cookie is silently dropped and the app breaks.
2. **With `secure: true`** — the cookie is sent cross-site, opening a
   CSRF surface that `sameSite: 'lax'` (the default) would have
   blocked for state-changing requests.

## Severity

`Medium`. Only set `sameSite: 'none'` when third-party embedding is
a hard requirement (federated SSO, embedded checkout widgets, etc.).

## Languages

JavaScript, TypeScript.

## What rastray flags

Cookie options with `sameSite: 'none'`:

```js
res.cookie('sid', token, { sameSite: 'none' });      // ← flagged

app.use(session({
  cookie: { sameSite: 'none', secure: true },        // ← flagged
}));
```

## What rastray deliberately does *not* flag

- `sameSite: 'lax'` (the browser default) or `sameSite: 'strict'`.
- Cookies with no `sameSite` field set explicitly.

## How to fix it

Prefer the strictest value that still lets the application work:

```js
res.cookie('sid', token, {
  sameSite: 'strict',   // safest; cookie never leaves first-party context
  secure: true,
  httpOnly: true,
});
```

`'lax'` is acceptable when top-level cross-site navigations need the
cookie (the common case for OAuth callbacks and login redirects).

If `'none'` is genuinely required (third-party iframe scenario), pair
it with `secure: true` **and** ensure every state-changing endpoint
has its own anti-CSRF mechanism (synchronizer token, double-submit
cookie). Suppress with an explanatory comment:

```js
// rastray-ignore: RSTR-COOKIE-003 — required for embedded checkout iframe; CSRF
//                  protected by per-request token in the X-CSRF-Token header
res.cookie('sid', token, { sameSite: 'none', secure: true, httpOnly: true });
```

## References

- [MDN: SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Chrome SameSite enforcement](https://blog.chromium.org/2020/02/samesite-cookie-changes-in-february.html)
