# RSTR-PERF-102 — `new Date()` inside a loop

## Summary

`new Date()` allocates a Date object whose only use is usually
`getTime()` or comparison. Doing it per iteration is gratuitous
allocation; `Date.now()` returns the milliseconds directly without
the object, and any of the comparisons/arithmetic you might want to
do work on the number.

If the Date itself is needed (formatting, locale), hoist it out of
the loop.

## Severity

`Low`. Pure overhead; matters at hot-path scale.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
for (const x of xs) {
    const t = new Date();                // ← flagged
    log(x, t.getTime());
}
```

## What rastray deliberately does *not* flag

- `Date.now()` calls.
- `new Date(value)` with an argument — that's a parse / construction
  that genuinely needs the constructor.
- Construction outside the loop.

## How to fix it

```js
// Need only the timestamp?
for (const x of xs) {
    log(x, Date.now());
}
```

```js
// Need the Date for formatting? Hoist it if loop-invariant:
const now = new Date();
for (const x of xs) {
    log(x, now.toISOString());
}
```

If you really need a fresh Date per iteration (rare — you almost
always want a single "now" for the entire batch), `Date.now()` plus
a single `new Date(ts)` at the end is cheaper.

## References

- [MDN: Date.now](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now)
