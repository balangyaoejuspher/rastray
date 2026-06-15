# RSTR-SSTI-002 — Node template compile from request input

## Summary

A Node template engine (`pug`, `handlebars`, `ejs`, `mustache`, …)
compiles a template string built from request input. The attacker
controls the template *source*, not just the data passed into a fixed
template — so they can execute arbitrary code through engine
internals, and SSTI usually escalates straight to RCE.

This is the Node counterpart of [`RSTR-SSTI-001`](./RSTR-SSTI-001.md).

## Severity

`High`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
const tmpl = pug.compile(req.body.template);              // ← flagged

handlebars.compile(req.query.body);                       // ← flagged

ejs.render(req.body.tpl, {});                             // ← flagged
```

## What rastray deliberately does *not* flag

- Rendering a fixed file: `pug.renderFile('views/index.pug', { data })`.
- Compiling a constant string at module load time.
- `ejs.render(fixedTemplate, dataFromReq)` where the template is a
  literal.

## How to fix it

Templates are code. Treat them like code: ship them with the
application, never accept them from clients. Always render a fixed
template and pass user input as **data**:

```js
// templates/email.ejs lives in the repo
const html = await ejs.renderFile(
  path.join(__dirname, 'templates/email.ejs'),
  { name: req.body.name, link: req.body.link }
);
```

If the product really needs user-provided "templates" (mail-merge,
report builder), use a sandboxed micro-syntax — not a full template
engine. Strict mustache (no helpers, no `{{{ raw }}}`) is the safest
pre-built option.

## References

- [PortSwigger: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
