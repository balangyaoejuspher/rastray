# RSTR-DJANGO-001 — settings file declares `DEBUG = True`

## Summary

A Django settings module ships with `DEBUG = True` hard-coded. When
this module is loaded in production, Django renders rich error
pages that include the full traceback, every entry in
`os.environ`, the active `SECRET_KEY`, database connection
strings, and the source of every template up to the failing call.
A single 500 response is enough to leak the keys to the castle.

The fix is to drive `DEBUG` from the environment with an explicit
false default, or keep `DEBUG = True` only in a dev-only settings
module that production never imports.

## Severity

`High`.

## Languages

Python (`.py`) inside a project whose Python manifest
(`pyproject.toml`, `requirements.txt`, `Pipfile`, `poetry.lock`,
or `uv.lock`) declares `django`.

## What rastray flags

```python
# settings.py
INSTALLED_APPS = [...]
MIDDLEWARE = [...]
DEBUG = True                      # ← flagged
ALLOWED_HOSTS = ['app.example.com']
```

Also flagged in:

- `settings/base.py`
- `settings/production.py`
- `settings/prod.py`
- any file whose basename is one of the above and which contains
  an `INSTALLED_APPS = ` or `MIDDLEWARE = ` declaration

## What rastray deliberately does *not* flag

`DEBUG` driven from the environment with a false-by-default:

```python
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'
```

`DEBUG = False`:

```python
DEBUG = False
```

`DEBUG = True` in a non-settings module (a test helper, a fixture,
a one-off script):

```python
# tests/helpers.py
DEBUG = True   # not flagged: file is not a Django settings module
```

`DEBUG = True` in a file that lacks the Django settings markers
(`INSTALLED_APPS` or `MIDDLEWARE`) — even if its basename is
`settings.py`, we won't flag it (it's a coincidentally-named
config file in a non-Django context).

## How to fix it

Use the environment variable pattern recommended in every
production-grade Django deployment:

```python
import os

DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'
```

Set `DJANGO_DEBUG=true` only in your local dev environment (`.env`
file, `direnv`, or your IDE's run config). Production stays at
the default `False`.

For the dev-vs-prod split-settings layout:

```text
settings/
    __init__.py
    base.py          # DEBUG never True; shared config
    dev.py           # DEBUG = True; from base import *
    production.py    # DEBUG = False; from base import *
```

In `manage.py` / `wsgi.py`, select the module by env var:

```python
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myapp.settings.production')
```

## How to suppress

If you're auditing a settings module that legitimately needs
`DEBUG = True` (e.g. a `settings/dev.py` that production never
loads), suppress per-line:

```python
# rastray-ignore: RSTR-DJANGO-001 — dev-only settings module, never imported in production
DEBUG = True
```

## References

- [Django — Deployment checklist (`DEBUG`)](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/#debug)
- [OWASP A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-489 — Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
