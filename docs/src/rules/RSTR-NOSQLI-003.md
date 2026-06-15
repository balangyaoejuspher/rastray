# RSTR-NOSQLI-003 — PyMongo filter built from `request.*`

## Summary

A PyMongo query is built by passing a request-derived dict (or `request.json`,
`request.form`, `request.values`) directly as the filter argument. An
attacker who submits `{"$gt": ""}` instead of a string causes the filter
to match every document — bypassing intended access controls.

This is the Python counterpart of [`RSTR-NOSQLI-001`](./RSTR-NOSQLI-001.md).

## Severity

`High`.

## Languages

Python (PyMongo / Motor).

## What rastray flags

```python
db.users.find_one(request.json)                  # ← flagged
db.posts.update_one(request.form, {'$set': ...}) # ← flagged
```

## What rastray deliberately does *not* flag

- Filters constructed from individual fields:
  `db.users.find_one({'_id': ObjectId(request.json['id'])})`.
- Filters built after `marshmallow` / `pydantic` schema validation.

## How to fix it

Validate and coerce inputs before building the filter. With pydantic:

```python
from pydantic import BaseModel
from bson import ObjectId

class UserQuery(BaseModel):
    id: str
    email: str | None = None

@app.post('/users')
def find_user(q: UserQuery = Depends(...)):
    return db.users.find_one({
        '_id':   ObjectId(q.id),
        'email': q.email,
    })
```

Plain dict construction also works as long as each field comes through
a per-field coercion (string, int, etc.) — the rule fires precisely
because passing the entire request object lets operator keys through.

## References

- [PyMongo: query operators](https://www.mongodb.com/docs/manual/reference/operator/query/)
- [OWASP NoSQL Injection](https://owasp.org/www-community/Injection_Flaws)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
