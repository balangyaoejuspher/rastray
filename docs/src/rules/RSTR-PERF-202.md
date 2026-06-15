# RSTR-PERF-202 — `time.sleep()` inside an `async def`

## Summary

`time.sleep()` is a blocking call. Inside an `async def`, it blocks
the entire event loop for the duration — every other coroutine that
should be making progress (HTTP clients, DB pools, background tasks)
stops as well. The cooperative-scheduler contract requires every
"wait" to go through `await`.

## Severity

`High`. The bug looks innocuous and the unit test still passes, but
production throughput collapses because the loop spends N×sleep_time
not doing anything.

## Languages

Python.

## What rastray flags

```python
async def poll():
    while True:
        check_status()
        time.sleep(5)                    # ← flagged
```

## What rastray deliberately does *not* flag

- `time.sleep()` in regular `def` functions (synchronous code; fine).
- `await asyncio.sleep(...)` — the correct form.
- `await trio.sleep(...)`, `await anyio.sleep(...)`.

## How to fix it

Replace with `asyncio.sleep`:

```python
import asyncio

async def poll():
    while True:
        check_status()
        await asyncio.sleep(5)
```

If the sleep is buried in a synchronous library call you cannot
modify, run that call in a thread executor so it doesn't block the
loop:

```python
import asyncio

async def call_blocking():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, blocking_thing)
```

## References

- [Python `asyncio.sleep` docs](https://docs.python.org/3/library/asyncio-task.html#sleeping)
- [PEP 492 — Coroutines](https://peps.python.org/pep-0492/)
