# RSTR-COOKIE-001 — cookie set without `secure: true`

## Summary

A session cookie is configured with `secure: false` (or no `secure`
flag at all). Browsers will send the cookie over plaintext HTTP, where
any on-path attacker (rogue Wi-Fi, an ISP, a hotel network) can read or
replay it.

## Severity

`High`. Session-cookie leakage means the attacker takes over the
authenticated session.

## Languages

JavaScript, TypeScript.

## What rastray flags

Express, Koa, Fastify, and `express-session` cookie option blocks
where `secure` is **explicitly false**:

```js
res.cookie('sid', token, { secure: false });        // ← flagged

app.use(session({
  secret: 'x',
  cookie: { secure: false },                         // ← flagged
}));
```

## What rastray deliberately does *not* flag

- Cookies set with `secure: true`.
- Cookies set with no `secure` field at all *inside* an `express-session`
  invocation where `cookie:` is also missing — that's a different bug,
  caught by static review, not this rule.
- Local-dev cookies inside an `if (NODE_ENV === 'development')` branch
  that the rule cannot semantically reach.

## How to fix it

Always set `secure: true` on session cookies. The full safe default is:

```js
res.cookie('sid', token, {
  secure: true,
  httpOnly: true,
  sameSite: 'strict',
});
```

For local development, terminate TLS at a reverse proxy (or use
`mkcert`) instead of toggling `secure` off.

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN: Secure cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies)
- [CWE-614: Sensitive Cookie Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
