# RSTR-NET-003 — Wildcard CORS with credentials, or bare wildcard ACAO

## Summary

Two adjacent misconfigurations:

1. **Wildcard origin + credentials.** `cors({ origin: '*', credentials: true })`
   (or the manual-header form) — browsers reject the combination, *and*
   if the code later "fixes" it by reflecting `Origin`, every site on
   the internet gets credentialed cross-origin access.

2. **Bare `Access-Control-Allow-Origin: *`** on an endpoint that
   returns sensitive data — even without credentials, the endpoint is
   exposing JSON cross-origin to anyone.

The second case is `Medium` severity (intent ambiguous), the first is
`High`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
app.use(cors({ origin: '*', credentials: true }));            // ← flagged
app.use(cors({ origin: true, credentials: true }));           // ← flagged
res.setHeader('Access-Control-Allow-Origin', '*');            // ← flagged (Medium)
```

## What rastray deliberately does *not* flag

- `cors({ origin: ['https://app.example.com'] })`.
- Static `Access-Control-Allow-Origin: https://app.example.com`.

## How to fix it

Allow-list specific origins; never combine wildcard with credentials:

```js
const ALLOWED = ['https://app.example.com', 'https://admin.example.com'];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED.includes(origin)) return cb(null, true);
    cb(new Error('not allowed'));
  },
  credentials: true,
}));
```

For a truly public API that returns *only* non-sensitive data,
`cors({ origin: '*' })` (no credentials) is fine — see
[`RSTR-CORS-002`](./RSTR-CORS-002.md) for the same vulnerability via
the manual-header form.

## References

- [Fetch spec — CORS protocol](https://fetch.spec.whatwg.org/#cors-protocol)
- [PortSwigger: CORS misconfiguration](https://portswigger.net/web-security/cors)
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html)
