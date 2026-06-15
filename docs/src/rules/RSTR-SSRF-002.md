# RSTR-SSRF-002 — Node `http`/`https` request with request input

## Summary

The same SSRF class as [`RSTR-SSRF-001`](./RSTR-SSRF-001.md), expressed
via Node's lower-level `http` / `https` core modules instead of `fetch`
or `axios`. An attacker controls the URL, the server makes the request,
and internal or cloud-metadata endpoints become reachable through the
application.

## Severity

`High`.

## Languages

JavaScript, TypeScript.

## What rastray flags

`http.get`, `http.request`, `https.get`, `https.request` with the URL
argument taken directly from `req.body.*`, `req.query.*`, `req.params.*`,
`req.headers.*`, or `req.cookies.*`:

```js
const http = require('http');

app.get('/proxy', (req, res) => {
  http.get(req.query.url, upstream => upstream.pipe(res));  // ← flagged
});
```

```js
https.request(req.body.target, opts, cb).end();             // ← flagged
```

## What rastray deliberately does *not* flag

- Literal URL arguments.
- Indirect flow (`const url = req.query.url; http.get(url)`) — same
  conservative scope as every other rastray taint rule.
- URLs constructed via `new URL(req.query.url, BASE)` where `BASE` is a
  fixed origin that the rule cannot evaluate. Suppress that case if
  the path component is also validated.

## How to fix it

Same playbook as `RSTR-SSRF-001`:

1. Parse the URL with `new URL(...)`.
2. Allow-list the hostname against a fixed `Set`.
3. Reject any URL that resolves to a private, loopback, or
   link-local address before making the upstream request.

```js
const ALLOWED = new Set(['api.example.com', 'cdn.example.com']);

app.get('/proxy', (req, res) => {
  let target;
  try { target = new URL(req.query.url); }
  catch { return res.status(400).end(); }
  if (!ALLOWED.has(target.hostname)) return res.status(400).end();
  https.get(target, upstream => upstream.pipe(res));
});
```

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
