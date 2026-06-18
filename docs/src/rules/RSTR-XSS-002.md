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

## Detection

This rule uses a tree-sitter AST query, not a regex. The
detector walks JavaScript / TypeScript / TSX assignment
expressions and only fires when:

1. The left-hand side is a `member_expression` whose property
   is exactly `innerHTML` or `outerHTML`.
2. The right-hand side's expression chain is rooted at one of:
   `location` (any member access — `location.hash`,
   `location.search`, `location.href`, etc.), `window.name`,
   `document.URL`, `document.cookie`, `document.referrer`,
   `document.baseURI`, or `document.documentURI`.
3. Trailing chains (`.toLowerCase()`, `.split('/')`, …) on
   the dom-source root are preserved as part of the same
   tainted expression.

Because detection is AST-based, the rule does **not** fire on:

- The same code inside a comment: `// el.innerHTML = location.hash;`
- The same code inside a string or template literal: `const docs = 'el.innerHTML = location.hash';`
- React JSX attributes such as `dangerouslySetInnerHTML={{ __html: location.hash }}` — the JSX attribute is not a JavaScript `assignment_expression`. (Whether that JSX shape *should* be flagged is the subject of a separate rule.)
- Files containing syntax errors — the AST parse fails gracefully and the analyzer returns zero findings rather than guessing.

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

