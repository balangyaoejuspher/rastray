# RSTR-NOSQLI-001 — Mongo find / update with req.body object

## Summary

A MongoDB query is built by passing an object straight from
`req.body` / `req.query` / `req.params` into the filter
position of `.find(...)`, `.findOne(...)`, `.updateOne(...)`,
etc. An attacker who submits JSON instead of the expected
form data (e.g. `{"user": {"$gt": ""}}` instead of
`{"user": "alice"}`) can use MongoDB's query operators
(`$gt`, `$ne`, `$regex`, `$where`) to bypass authentication
or extract every document.

## Severity

`High`.

## Languages

JavaScript / TypeScript.

## How to fix it

Coerce every value to its expected primitive type:

```js
// SAFE — even if req.body.user is `{"$gt": ""}`, String()
// flattens it to '[object Object]' which matches nothing.
users.findOne({ user: String(req.body.user) });
```

Or validate with a schema:

```js
import { z } from 'zod';
const Q = z.object({ user: z.string() });
const { user } = Q.parse(req.body);
users.findOne({ user });
```

## References

- [OWASP: NoSQL injection](https://owasp.org/www-community/Injection_Theory)
- [Snyk: How NoSQL injection works](https://snyk.io/learn/nosql-injection/)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
