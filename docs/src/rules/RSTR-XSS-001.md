# RSTR-XSS-001 — reflected XSS via res.send / res.end / res.write

## Summary

An Express handler writes a value from `req.body.*`,
`req.query.*`, `req.params.*`, `req.cookies.*`, or
`req.headers.*` directly into the HTTP response via
`res.send(...)`, `res.end(...)`, or `res.write(...)`. An
attacker can supply `<script>alert(1)</script>` (or
something less obvious) and the browser will execute it as
HTML.

## Severity

`High`.

## Languages

JavaScript, TypeScript (and JSX / TSX / .mjs / .cjs).

## How to fix it

Send JSON instead of HTML when possible:

```js
res.json({ greeting: req.body.greeting });
```

Or HTML-escape:

```js
import he from 'he';
res.send(`<p>${he.encode(req.body.greeting)}</p>`);
```

Don't write a custom escaper — `he` and similar libraries
handle the edge cases (entity references, surrogate pairs,
context-specific encoding).

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
