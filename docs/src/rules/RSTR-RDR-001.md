# RSTR-RDR-001 — Express res.redirect(req.x)

## Summary

`res.redirect(...)` is called with a value taken directly
from `req.body.*`, `req.query.*`, or `req.params.*`. An
attacker can craft a link like
`https://yoursite.com/go?next=https://evil.com/login` —
the URL bar still says yoursite.com, the user clicks the
link from a "trusted" source, gets redirected to evil.com,
sees a copy of the login page, and types their password.

Open redirect is the workhorse of phishing campaigns.

## Severity

`Medium`. Real impact, but lower than direct code-execution
sinks.

## How to fix it

Allow-list the targets:

```js
const SAFE_PATHS = new Set(['/dashboard', '/profile', '/settings']);

if (!SAFE_PATHS.has(req.query.next)) {
  return res.status(400).send('invalid redirect target');
}
res.redirect(req.query.next);
```

Or restrict to same-origin redirects with a single leading
slash:

```js
const target = req.query.next || '/';
if (!target.startsWith('/') || target.startsWith('//')) {
  return res.redirect('/');
}
res.redirect(target);
```

## References

- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
