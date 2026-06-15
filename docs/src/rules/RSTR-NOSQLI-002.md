# RSTR-NOSQLI-002 — Mongo `$where` with request input

## Summary

`$where` in MongoDB lets the caller supply a **JavaScript
function** that runs server-side inside the database
process for every document. If the value of `$where` comes
from request input, the attacker can run arbitrary
JavaScript — essentially **remote code execution in the
database process**.

## Severity

`Critical`. This is RCE, not just data exposure.

## Languages

JavaScript / TypeScript.

## How to fix it

**Don't use `$where`.** Refactor to a structured filter
expression that uses standard MongoDB operators:

```js
// BAD: $where with user input — RCE
users.find({ $where: `this.balance > ${req.query.min}` });

// GOOD: structured filter
users.find({ balance: { $gt: Number(req.query.min) } });
```

If you genuinely need `$where`-level expressiveness, ask
why — almost every legitimate use can be rewritten as a
combination of `$expr`, `$lookup`, `$elemMatch`, etc., none
of which evaluate user JavaScript.

## References

- [MongoDB docs: $where (security warning)](https://www.mongodb.com/docs/manual/reference/operator/query/where/)
- [MongoDB server-side scripting](https://www.mongodb.com/docs/manual/core/server-side-javascript/)
