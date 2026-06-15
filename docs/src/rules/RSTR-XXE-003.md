# RSTR-XXE-003 — libxmljs `parseXml(..., { noent: true })`

## Summary

`libxmljs2` (and the original `libxmljs`) accepts XML with the
`noent: true` option, which expands external entities. A malicious
document then reads local files or makes outbound requests through the
Node process — same vulnerability class as the lxml variant.

## Severity

`High`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
const libxmljs = require('libxmljs2');
const doc = libxmljs.parseXml(payload, { noent: true });    // ← flagged
```

## What rastray deliberately does *not* flag

- `libxmljs.parseXml(payload)` (default options — `noent` is `false`).
- `libxmljs.parseXml(payload, { noent: false })`.

## How to fix it

Drop the `noent: true` option:

```js
const doc = libxmljs.parseXml(payload);   // entity expansion off by default
```

If you genuinely need to expand entities from a *trusted* document
(e.g. a build-time XML config you author yourself), keep the option
but suppress with a comment explaining provenance:

```js
// rastray-ignore: RSTR-XXE-003 — internal config, never user-supplied
const doc = libxmljs.parseXml(internalCfg, { noent: true });
```

## References

- [`libxmljs2` README](https://github.com/marudor/libxmljs2#readme)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [CWE-611](https://cwe.mitre.org/data/definitions/611.html)
