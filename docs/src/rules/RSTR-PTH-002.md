# RSTR-PTH-002 — Express `res.sendFile` / `fs.readFile` with request input

## Summary

Node counterpart of [`RSTR-PTH-001`](./RSTR-PTH-001.md). The
application reads, writes, or streams a file whose path is built from
`req.params`, `req.query`, or `req.body` without confining the result
to a safe base directory.

## Severity

`High`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
app.get('/file', (req, res) => {
    res.sendFile(req.query.path);                              // ← flagged
});

fs.readFile(req.params.name, (err, data) => { ... });          // ← flagged
fs.writeFileSync(req.body.dest, data);                         // ← flagged
```

## What rastray deliberately does *not* flag

- `res.sendFile(path.join(SAFE_DIR, basename(req.params.name)))` —
  the `basename` strips traversal sequences.
- Constant paths.

## How to fix it

Always join the user input onto a fixed base, run it through
`path.basename` to strip `../`, and verify the resolved path still
sits under the base:

```js
import path from 'node:path';
const BASE = path.resolve('./uploads');

app.get('/file/:name', (req, res) => {
    const safeName = path.basename(req.params.name);
    const target   = path.resolve(BASE, safeName);
    if (!target.startsWith(BASE + path.sep)) {
        return res.sendStatus(404);
    }
    res.sendFile(target);
});
```

`path.resolve` collapses any leftover `../`; the prefix check then
catches symlink escapes.

## References

- [Express `res.sendFile`](https://expressjs.com/en/api.html#res.sendFile)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
