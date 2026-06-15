# RSTR-PTH-001 — Flask `send_file(request.*)`

## Summary

A Flask handler calls `send_file` (or `send_from_directory` with the
path on the wrong argument) using a path derived directly from
request input. An attacker submits `../../etc/passwd` and the server
happily reads and returns that file.

## Severity

`High`.

## Languages

Python (Flask / Quart).

## What rastray flags

```python
@app.route('/download')
def download():
    return send_file(request.args['path'])         # ← flagged
```

```python
@app.route('/file')
def file():
    return send_file(f'./uploads/{request.args["name"]}')   # ← flagged
```

## What rastray deliberately does *not* flag

- `send_from_directory(safe_dir, secure_filename(name))` (the
  documented safe form).
- `send_file(...)` with a constant path.

## How to fix it

Use `send_from_directory` with `werkzeug.utils.secure_filename`:

```python
from flask import send_from_directory
from werkzeug.utils import secure_filename

@app.route('/file/<name>')
def file(name):
    return send_from_directory(
        directory='./uploads',
        path=secure_filename(name),
    )
```

For multi-tenant uploads, also confirm the resolved path stays inside
the intended base directory:

```python
import os
base = os.path.realpath('./uploads')
target = os.path.realpath(os.path.join(base, secure_filename(name)))
if not target.startswith(base + os.sep):
    abort(404)
```

`secure_filename` only strips path separators and a handful of unsafe
chars — the `realpath` check catches symlink shenanigans.

## References

- [Flask: send_file / send_from_directory](https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory)
- [OWASP Path Traversal Cheat Sheet](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
