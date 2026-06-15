# RSTR-DES-004 — Node `node-serialize` `unserialize`

## Summary

The `node-serialize` package's `unserialize` function explicitly
documents that it executes embedded JavaScript when the payload
contains an `IIFE`. CVE-2017-5941 demonstrated remote code execution
with a one-line payload. The package is unmaintained; using it on
untrusted input is direct RCE.

## Severity

`Critical`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.body.payload);   // ← flagged
```

```js
import { unserialize } from 'node-serialize';
const obj = unserialize(rawString);                     // ← flagged
```

## What rastray deliberately does *not* flag

- `JSON.parse(...)` — data only.
- `structuredClone(...)` — structured-clone algorithm, no code paths.
- `msgpack.decode(...)` / `cbor.decode(...)`.

## How to fix it

Stop using `node-serialize`. For trusted data, `JSON.stringify` /
`JSON.parse` round-trips primitives, arrays, and plain objects. For
binary or richer types, use MessagePack or CBOR.

```js
// Bad
const obj = serialize.unserialize(blob);

// Good (for any data-only use)
const obj = JSON.parse(blob);
```

Remove `node-serialize` from `package.json` and audit transitive
dependencies (`npm ls node-serialize`) — old build tools sometimes
still pull it in.

## References

- [CVE-2017-5941](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)
- [Node.js Security — RCE via unserialize](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
