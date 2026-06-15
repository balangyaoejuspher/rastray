# RSTR-CORS-002 — manual `Access-Control-Allow-Origin: *` with credentials

## Summary

Code sets the `Access-Control-Allow-Origin` response header to `*` on
a route that also sends `Access-Control-Allow-Credentials: true`. The
CORS spec forbids that combination — browsers reject the response and
the request fails — *and* if the application later "fixes" it by
reflecting the request `Origin` header without an allow-list, every
third-party origin gets credentialed cross-origin access to the API.

This is the same vulnerability class as `RSTR-CORS-001`, just expressed
via the lower-level `res.setHeader` / `res.header` API instead of the
`cors` middleware.

## Severity

`High`.

## Languages

JavaScript, TypeScript.

## What rastray flags

Manual header writes pairing wildcard ACAO with credentials:

```js
res.setHeader('Access-Control-Allow-Origin', '*');           // ← flagged
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

```js
res.header('Access-Control-Allow-Origin', '*');              // ← flagged
res.header('Access-Control-Allow-Credentials', true);
```

## What rastray deliberately does *not* flag

- `Access-Control-Allow-Origin: *` without credentials (the public-API
  pattern; the spec permits it).
- Headers set against a fixed allow-listed origin string.

## How to fix it

Allow-list specific origins and only echo when the request `Origin`
matches an entry. The minimum safe pattern is:

```js
const ALLOWED = new Set([
  'https://app.example.com',
  'https://admin.example.com',
]);

const origin = req.headers.origin;
if (origin && ALLOWED.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');
}
```

`Vary: Origin` is essential — without it caches will serve the
allow-listed origin's response to other requesters.

## How to suppress

For public, credential-less APIs the wildcard is correct; just remove
the `Allow-Credentials` line. If your tooling has a reason to keep
both headers, suppress per-line:

```js
// rastray-ignore: RSTR-CORS-002 — public docs endpoint, no credentials sent
```

## References

- [Fetch spec: CORS protocol — credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)
- [PortSwigger: CORS misconfiguration](https://portswigger.net/web-security/cors)
- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
