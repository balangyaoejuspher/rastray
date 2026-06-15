# RSTR-XSS-002 — DOM-based XSS via innerHTML / outerHTML

## Summary

A DOM property (`.innerHTML` or `.outerHTML`) is assigned
from a browser-supplied source like `location.hash`,
`window.name`, `document.cookie`, or `document.referrer`.
Anyone who can craft a URL the victim visits can run
arbitrary JS in their browser.

## Severity

`High`.

## Languages

JavaScript, TypeScript (and JSX / TSX / .mjs / .cjs).

## How to fix it

Use `.textContent` instead — it never parses HTML:

```js
el.textContent = location.hash;   // ← safe
```

Or, if HTML rendering is genuinely required, sanitise with
[DOMPurify](https://github.com/cure53/DOMPurify) first:

```js
import DOMPurify from 'dompurify';
el.innerHTML = DOMPurify.sanitize(location.hash);
```

Never write a custom HTML sanitiser. The list of edge cases
is enormous (SVG, MathML, mutation XSS, mXSS in legacy
browsers) and only well-maintained libraries keep up.

## References

- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [DOMPurify](https://github.com/cure53/DOMPurify)
