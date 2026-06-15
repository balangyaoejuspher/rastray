# RSTR-CRY-005 — `Math.random()` used for security

## Summary

`Math.random()` is not a cryptographically secure RNG. Its output is
fully predictable from a small handful of observed samples. Using it
to generate session tokens, password-reset codes, OAuth nonces, API
keys, or any other security-sensitive value lets an attacker forge
those values offline.

## Severity

`Medium`. (We picked `Medium` over `High` because the rule fires at
every `Math.random()` site and not all of them are security-relevant;
when the value is in fact a token, it is unambiguously critical.)

## Languages

JavaScript, TypeScript.

## What rastray flags

Any `Math.random()` call:

```js
const token = Math.random().toString(36).slice(2);   // ← flagged
```

## What rastray deliberately does *not* flag

- `crypto.randomUUID()`, `crypto.getRandomValues(...)`, `crypto.randomBytes(...)`.

## How to fix it

Use the platform-provided CSPRNG:

```js
// Browser
const arr = new Uint8Array(16);
crypto.getRandomValues(arr);
const token = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');

// or, even simpler:
const token = crypto.randomUUID();          // available in modern browsers and Node 19+
```

```js
// Node
import { randomBytes, randomUUID } from 'crypto';

const token = randomBytes(16).toString('hex');
const id    = randomUUID();
```

For non-security uses — animation jitter, sampling, shuffles in a
single-player game — `Math.random()` is fine. If a finding is in
clearly non-security code, suppress it per-line with a comment.

## References

- [MDN: `Crypto.getRandomValues()`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
- [Node `crypto.randomUUID`](https://nodejs.org/api/crypto.html#cryptorandomuuidoptions)
- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator](https://cwe.mitre.org/data/definitions/338.html)
