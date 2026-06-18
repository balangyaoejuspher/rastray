# RSTR-PERF-101 — `await` inside a loop

## Summary

A `for` / `while` loop body awaits a Promise. Each iteration blocks
until the previous one resolves, so N independent async calls take
the sum of their latencies instead of the maximum. The loop is
effectively serial despite the async machinery.

`Promise.all` (or `Promise.allSettled`) parallelizes them.

## Severity

`Low`. Treat as advisory rather than fix-me. Real production code
has many legitimate sequential `await`-in-loop patterns
(pagination, transactional iteration, rate-limited APIs,
stream consumption, ordered side effects) where this rule is
a true positive but the suggested `Promise.all` rewrite
does not apply.

When the loop body's awaits are genuinely independent, the
wall-clock difference is often 5×-20× for I/O loops —
worth the rewrite. When they are not, suppress with a
comment explaining the constraint.

## Languages

JavaScript, TypeScript.

## What rastray flags

The rule fires on every `await` inside a loop body. Whether
the finding is *actionable* depends on the loop shape.

Likely-actionable shapes (the rewrite to `Promise.all`
helps):

```js
const results = [];
for (const id of ids) {
    results.push(await fetch(`/items/${id}`));     // ← flagged, fixable
}
```

Legitimately-sequential shapes (the rule still fires; the
rewrite does not apply — suppress instead):

```js
// Pagination: next cursor depends on previous result
while (hasMore) {
    const page = await api.next(cursor);            // ← flagged, NOT fixable
    cursor = page.nextCursor;
    hasMore = page.hasMore;
}

// Transactional iteration: shared `tx` requires sequencing
for (const row of rows) {
    await tx.update(row.id, { processed: true });   // ← flagged, NOT fixable
}

// Stream consumption: `for await ... of` is inherently sequential
for await (const chunk of readable) {
    await sink.write(chunk);                        // ← flagged, NOT fixable
}

// Rate-limited APIs: sequencing is intentional
for (const item of items) {
    await respectfulApi.post(item);                 // ← flagged, NOT fixable
    await sleep(100);
}
```

## What rastray deliberately does *not* flag

- Sequential awaits *outside* a loop.
- `await` at the top level of an `async function` (no enclosing loop).

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
