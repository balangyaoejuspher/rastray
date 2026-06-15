# RSTR-INJ-003 — `eval` / `exec` / `new Function` — dynamic code execution

## Summary

The application evaluates a string as code at runtime. If any part of
that string is influenced by request input, the attacker controls the
program counter — an immediate full RCE. Even when the input is
trusted, dynamic evaluation defeats every static analyzer (rastray,
the type-checker, the IDE), so the trade-off is rarely worth it.

## Severity

`Critical` when the input may be user-controlled; `High` otherwise.

## Languages

Python, JavaScript, TypeScript, PHP.

## What rastray flags

- Python: `eval(...)`, `exec(...)`, `compile(...)` followed by `eval`/`exec`.
- JavaScript / TypeScript: `eval(...)`, `new Function(...)`, `setTimeout(stringArg, ...)`, `setInterval(stringArg, ...)`.
- PHP: `eval(...)`, `assert($x)` with a string argument.

## What rastray deliberately does *not* flag

- `JSON.parse(...)` — structured data, not code.
- `Function(...)` calls used purely for static reflection (`Function.prototype.toString`).
- AST evaluators in a sandbox (`vm2`, `tiny-eval` etc.) — they have
  separate threat models; the rule's blanket flag is still warranted,
  suppress with an explanatory comment.

## How to fix it

Replace dynamic evaluation with a parser / dispatcher:

```python
# Bad — math expressions from user input
result = eval(request.args['expr'])

# Good — expression parser library
from simpleeval import simple_eval
result = simple_eval(request.args['expr'])
```

For JS configuration that historically motivated `new Function`, the
modern alternatives are JSON, YAML, or a typed schema:

```js
// Bad — interpret arbitrary user JS
const transform = new Function('row', userJs);

// Good — accept a small DSL
const transform = compileTransform(parseDsl(userDsl));
```

If you must keep `eval`, *severely* restrict the input grammar at the
boundary and document the threat model in source.

## References

- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [MDN: never use `eval()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
