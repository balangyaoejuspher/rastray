# RSTR-REDOS-001 — nested quantifier catastrophic backtracking

## Summary

A regex contains a nested quantifier of the form `(X+)+`,
`(X*)+`, or `(X+)*`. On crafted input like
`aaaaaaaaaaaaaaaaaaab` (lots of `a`s followed by a `b`
that breaks the match), backtracking regex engines try
exponentially many ways to partition the input between the
inner and outer quantifier — `O(2ⁿ)` work that hangs the
thread.

This is **regular-expression denial of service** (ReDoS).
A single user-controlled string can DoS a server thread for
minutes.

## Severity

`High`. Cheap to exploit, hard to recover from once the
process is locked up.

## Languages

JavaScript, TypeScript, Python.

## What rastray flags

Regex literals (`/^(a+)+$/`), `new RegExp('^(a+)+$')`, and
`re.compile(r'^(a+)+$')` containing the nested-quantifier
shape.

## What rastray deliberately does *not* flag

- Simple single quantifiers: `/^a+$/`, `r'^[a-z]+$'`.
- Character classes: `/^[a-z0-9]+$/`.
- Alternation overlap (`(a|a)+`, `(ab|a)+`) — same risk
  class but needs a regex parser to detect. Out of scope
  for this rule; a future slice may add it.

## How to fix it

Three options:

1. **Collapse the nested quantifier:** `(a+)+` →  `a+`
   when both branches accept the same character class.

2. **Use a character class instead of alternation:**
   `(a|b)+` → `(?:[ab])+`.

3. **Use a linear-time regex engine.** JS engines, PCRE,
   and Python's `re` all use backtracking. Switch to:
   - Rust's [`regex` crate](https://docs.rs/regex/)
   - Google's [RE2](https://github.com/google/re2)
   - The [`re2-wasm`](https://www.npmjs.com/package/re2-wasm) JS port
   - Python's [`regex`](https://pypi.org/project/regex/)
     module in `LOCALE`-free mode is still backtracking;
     for guaranteed linear time use Rust regex via PyO3 or
     [`google-re2`](https://pypi.org/project/google-re2/).

4. **Validate input length** before matching as
   defence-in-depth. Even with a backtracking engine,
   capping input at 1 KB stops most DoS shapes from
   running long enough to matter.

## References

- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [`safe-regex` heuristic the original detection comes from](https://github.com/davisjam/safe-regex)
- [Cloudflare 2019 outage caused by ReDoS](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/)
- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
