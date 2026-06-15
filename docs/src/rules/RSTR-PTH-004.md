# RSTR-PTH-004 — literal `../../` in source

## Summary

A literal `'../../'` (or longer) string appears inside source code.
Most of the time this is build-tool plumbing or test-fixture pathing —
**not** a vulnerability — but it is also exactly the shape of a
hard-coded directory-traversal payload, so the rule flags it for
review.

## Severity

`Info`. This is a flag-for-review, not a confirmed bug.

## Languages

All scanned languages — Python, JS/TS, Go, Rust, Java, Kotlin, Ruby, PHP.

## What rastray flags

```python
ROOT = '../../config/settings.yaml'        # ← flagged
```

```js
import x from '../../shared/util';          // ← rule excludes import statements; not flagged
```

The rule **does** exclude `import` / `require` / `from … import …`
specifiers, and **does** exclude lines that are recognisably module
imports. It fires on the remaining cases where the `../../` is in an
expression context.

## What rastray deliberately does *not* flag

- `import 'pkg/../../sub'` (module specifiers).
- TypeScript `path mapping` in `tsconfig.json` `paths`.

## How to fix it

If the `../../` is intentional (build-time path, test fixture), keep
it and suppress the finding with a comment that documents *why*:

```python
# rastray-ignore: RSTR-PTH-004 — fixture lives outside the package
ROOT = '../../tests/fixtures/sample.json'
```

If the literal is in fact concatenated into a path that takes
attacker input downstream, refactor to a real allow-list of file
roots and use `os.path.realpath` to confirm the resolution stays
inside.

## References

- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
