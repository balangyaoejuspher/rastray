# RSTR-DES-003 — Python `marshal.loads` on untrusted input

## Summary

`marshal` is a Python-internal serializer used by the compiler for
`.pyc` files. It is not a general-purpose data format and the docs
explicitly warn against using it on untrusted input — `marshal.loads`
can construct code objects which `exec` will then execute.

## Severity

`Critical`.

## Languages

Python.

## What rastray flags

```python
import marshal
obj = marshal.loads(request.data)                  # ← flagged
obj = marshal.load(open('payload.bin', 'rb'))      # ← flagged
```

## What rastray deliberately does *not* flag

- Reads of `.pyc` files by the import system (handled internally; the
  rule fires on user-level `marshal.load(s)` calls).
- `json.loads`, `tomllib.loads`, `msgpack.unpackb`.

## How to fix it

Use a data format. JSON for short data, MessagePack or CBOR for
binary, Protocol Buffers or Cap'n Proto for schemas. None of those
can construct executable Python objects.

```python
import json
obj = json.loads(request.data)
```

There is no safe-mode `marshal`. If you find marshal in production
code outside the import machinery, treat the discovery as a P0 and
replace.

## References

- [Python `marshal` docs — warning](https://docs.python.org/3/library/marshal.html)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
