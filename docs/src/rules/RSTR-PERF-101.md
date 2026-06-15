# RSTR-PERF-101 — `await` inside a loop

## Summary

A `for` / `while` loop body awaits a Promise. Each iteration blocks
until the previous one resolves, so N independent async calls take
the sum of their latencies instead of the maximum. The loop is
effectively serial despite the async machinery.

`Promise.all` (or `Promise.allSettled`) parallelizes them.

## Severity

`Medium`. The wall-clock difference is often 5×-20× for I/O loops.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
const results = [];
for (const id of ids) {
    results.push(await fetch(`/items/${id}`));     // ← flagged
}
```

```js
while (hasMore) {
    const page = await api.next();                  // ← flagged
    pages.push(page);
}
```

## What rastray deliberately does *not* flag

- Sequential awaits *outside* a loop.
- Loops where the result of iteration N is the input to iteration N+1
  (the loop is genuinely sequential by design).
- Rate-limited iteration where serialization is intentional —
  suppress with a comment explaining the limit.

## How to fix it

Map → `Promise.all`:

```js
const results = await Promise.all(
    ids.map(id => fetch(`/items/${id}`))
);
```

For partial-failure tolerance:

```js
const results = await Promise.allSettled(
    ids.map(id => fetch(`/items/${id}`))
);
const ok    = results.filter(r => r.status === 'fulfilled').map(r => r.value);
const fail  = results.filter(r => r.status === 'rejected');
```

For genuinely long lists, batch:

```js
const out = [];
for (let i = 0; i < ids.length; i += 10) {
    const batch = ids.slice(i, i + 10);
    out.push(...await Promise.all(batch.map(id => fetch(`/items/${id}`))));
}
```

## References

- [MDN: Promise.all](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/all)
- [ESLint rule: `no-await-in-loop`](https://eslint.org/docs/latest/rules/no-await-in-loop)
