# RSTR-DES-001 — Python `pickle.loads` on untrusted input

## Summary

`pickle.loads` (and `Unpickler.load`) deserializes arbitrary Python
objects, including ones whose constructors execute side-effectful
code. A `pickle` byte string is **a program**; the only safe input is
data you yourself produced and stored in a location only you can write
to. From the network, from a database row a user wrote, from a file
upload — never.

This is the single most common Python RCE primitive.

## Severity

`Critical`.

## Languages

Python.

## What rastray flags

```python
import pickle
obj = pickle.loads(request.data)                   # ← flagged
obj = pickle.load(open('user_uploaded.pkl', 'rb')) # ← flagged
```

```python
from pickle import Unpickler
obj = Unpickler(stream).load()                     # ← flagged
```

## What rastray deliberately does *not* flag

- `json.loads(...)`, `tomllib.loads(...)`, `msgpack.unpackb(...)` —
  data-only formats.
- `dill`, `cloudpickle` — *also* unsafe (same primitive); they have
  separate rules.

## How to fix it

For data interchange, use JSON or MessagePack. For storing typed
Python objects, use `pydantic` / `attrs` / `dataclasses` with explicit
`from_dict` constructors:

```python
import json
from pydantic import BaseModel

class Job(BaseModel):
    id: str
    payload: dict

job = Job.model_validate_json(request.data)
```

If you absolutely must use pickle (long-lived internal cache, no
external surface), sign the payload with HMAC-SHA-256 and verify
before unpickling. That moves the threat model from "anyone with
write access to the channel can RCE you" to "anyone with the HMAC key
can RCE you" — better, but still demand a real reason.

## References

- [Python `pickle` security warning](https://docs.python.org/3/library/pickle.html#module-pickle)
- [PortSwigger: Insecure deserialization](https://portswigger.net/web-security/deserialization)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
