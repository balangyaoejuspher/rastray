# RSTR-XSS-003 — `document.write` with attacker-controlled DOM data

## Summary

`document.write` (or `document.writeln`) is called with a string built
from `window.location.*`, `document.referrer`, `document.URL`, or
similar URL-bar / referrer sources — all directly controllable by an
attacker via a crafted link. The HTML is parsed in the page's origin,
yielding DOM-based XSS.

## Severity

`High`. Indistinguishable from reflected XSS in impact.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
document.write(location.search);              // ← flagged
document.writeln(document.referrer);          // ← flagged
document.write('<h1>' + location.hash + '</h1>');  // ← flagged
```

## What rastray deliberately does *not* flag

- `document.write(staticString)` with a literal argument.
- `document.write(value)` where `value` is computed from a server
  response — those go through `RSTR-XSS-001` / `RSTR-XSS-002` paths.
- `document.write` of values that were *first* run through a
  sanitiser (DOMPurify, `escapeHtml`). The rule cannot see across
  calls; if the data was sanitised, suppress per-line.

## How to fix it

Stop using `document.write` entirely. Modern alternatives:

- For text: `element.textContent = ...` (safe; no HTML parsing).
- For attributes: `element.setAttribute('href', ...)`.
- For controlled markup: `element.innerHTML = DOMPurify.sanitize(html)`.

If you must accept HTML, sanitise it explicitly:

```js
import DOMPurify from 'dompurify';
container.innerHTML = DOMPurify.sanitize(untrusted, { USE_PROFILES: { html: true } });
```

Note that `document.write` *after* the page has loaded silently wipes
the entire document — there is no production scenario where it is the
right primitive.

## References

- [OWASP DOM-XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN: `document.write`](https://developer.mozilla.org/en-US/docs/Web/API/Document/write) — section "Notes"
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
