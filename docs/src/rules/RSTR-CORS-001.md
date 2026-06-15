# RSTR-CORS-001 — cors origin:true|* with credentials:true

## Summary

Express's `cors` middleware is configured with both
`origin: true` (or `'*'`) **and** `credentials: true`. The
browser-spec dance for this combination collapses the
wildcard to the request's `Origin` header and accepts
cookies with the response. Net effect: any origin in the
world can make credentialed cross-site requests to your
API, defeating same-origin policy.

## Severity

`High`.

## Languages

JavaScript / TypeScript.

## How to fix it

Allow-list the trusted origins:

```js
app.use(cors({
  origin: ['https://app.example.com', 'https://admin.example.com'],
  credentials: true,
}));
```

Or — if the API is truly public — drop `credentials`:

```js
app.use(cors({ origin: '*' }));   // public API, no cookies
```

Function-form for dynamic allow-listing:

```js
const ALLOWED = new Set(['https://app.example.com']);
app.use(cors({
  origin: (origin, cb) => cb(null, ALLOWED.has(origin)),
  credentials: true,
}));
```

## References

- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN: Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger: CORS misconfiguration](https://portswigger.net/web-security/cors)
