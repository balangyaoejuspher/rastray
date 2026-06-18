# RSTR-FLASK-001 — Flask app enables the Werkzeug debugger

## Summary

A Flask application is started with `debug=True`, or the
equivalent `app.config['DEBUG'] = True` / `app.debug = True`.
When this code is reached in production, any unhandled exception
renders the Werkzeug interactive debugger — and that debugger
exposes an in-browser Python console at `/console` that executes
arbitrary code inside the running process.

Modern Werkzeug versions pin-protect the console with a numeric
PIN derived from machine metadata (`uuid.getnode()`, the user
running the process, the location of `flask/app.py` on disk).
That PIN is **not a real authentication boundary**: the inputs
are deterministic and several have been demonstrated as
recoverable through other information-disclosure bugs (file
read primitives, container metadata endpoints, careful log
inspection). Treat `debug=True` in production as remote code
execution by default.

## Severity

`Critical`.

## Languages

Python (`.py`) inside a project whose Python manifest
(`pyproject.toml`, `requirements.txt`, `Pipfile`, `poetry.lock`,
or `uv.lock`) declares `flask`.

## What rastray flags

```python
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "hello"

if __name__ == "__main__":
    app.run(debug=True)              # ← flagged
```

Also flagged:

```python
app.run(host="0.0.0.0", port=5000, debug=True)   # ← flagged
app.config["DEBUG"] = True                       # ← flagged
app.debug = True                                 # ← flagged
```

## What rastray deliberately does *not* flag

`debug` driven from the environment with a false-by-default:

```python
import os
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
```

```python
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG") == "1"
```

`app.run()` without the `debug` keyword (defaults to `False` in
Flask):

```python
app.run(host="127.0.0.1", port=5000)
```

`debug=False` explicitly:

```python
app.run(debug=False)
```

Files that don't import Flask at all are not flagged even when
they contain a `debug=True` keyword on some unrelated object.

## How to fix it

Drive `debug` from the environment with an explicit false
default:

```python
import os
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
```

For the config form:

```python
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG") == "1"
```

In production, set `FLASK_DEBUG` to nothing (or `0`). In dev,
set `FLASK_DEBUG=1` in your local shell, `.env`, or IDE run
config.

Prefer running production traffic through a real WSGI/ASGI
server (`gunicorn`, `uwsgi`, `hypercorn`) — `app.run()` is
intended for development only. Production WSGI servers ignore
`app.debug` for request handling, but a stray `debug=True` still
sets `app.debug = True` on the process, which other code paths
may check.

## How to suppress

If you're auditing a dev-only entrypoint that production never
loads (a `Makefile` target, a local launcher script), suppress
per-line with a reason:

```python
# rastray-ignore: RSTR-FLASK-001 — dev launcher, never invoked in production
app.run(debug=True)
```

## References

- [Flask — Debug Mode](https://flask.palletsprojects.com/en/latest/quickstart/#debug-mode)
- [Werkzeug — Debugger PIN security](https://werkzeug.palletsprojects.com/en/latest/debug/#debugger-pin)
- [OWASP A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-489 — Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
