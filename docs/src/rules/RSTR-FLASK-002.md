# RSTR-FLASK-002 — Flask `SECRET_KEY` assigned from a string literal

## Summary

A Flask application sets `SECRET_KEY` to a string literal in
source code. Flask uses this key to sign every session cookie,
every CSRF token (via Flask-WTF), and every `itsdangerous`-signed
URL the app issues — all with HMAC-SHA256. Anyone who can read
the key can forge a valid session cookie for any user, including
admin, and submit forged CSRF-protected POSTs.

The source repository is one of many places the key can leak
from: container images on a public registry, Sentry traces,
log shipping, support tickets, screenshots in PR review tools.
The fix is the same regardless: load the key from a secret store
(or env var) at startup, and rotate it if it ever leaks.

## Severity

`High`.

## Languages

Python (`.py`) inside a project whose Python manifest
(`pyproject.toml`, `requirements.txt`, `Pipfile`, `poetry.lock`,
or `uv.lock`) declares `flask`.

## What rastray flags

```python
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-in-production"   # ← flagged
```

Also flagged:

```python
app.secret_key = "dev-secret-please-change"            # ← flagged
app.config['SECRET_KEY'] = 'super-secret-xyz'          # ← flagged
```

## What rastray deliberately does *not* flag

Env-driven loads:

```python
import os
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "")
```

Generated-at-startup keys:

```python
import secrets
app.config["SECRET_KEY"] = secrets.token_hex(32)
```

Computed / f-string values:

```python
app.config["SECRET_KEY"] = f"derived-{base}"
```

Configuration loaded from external sources:

```python
app.config.from_envvar("FLASK_CONFIG")
app.config.from_object("myapp.settings.Production")
```

Files that don't import Flask are not flagged even if they assign
a `SECRET_KEY` literal.

## How to fix it

Load the key from a secret store or environment variable at
startup, with a *missing-key-is-fatal* default:

```python
import os
from flask import Flask

app = Flask(__name__)
try:
    app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
except KeyError as exc:
    raise SystemExit("FLASK_SECRET_KEY env var is required") from exc
```

Generate a fresh value per environment:

```bash
python -c 'import secrets; print(secrets.token_hex(32))'
```

Store the value in your platform's secret manager (AWS Secrets
Manager, GCP Secret Manager, HashiCorp Vault, GitHub Actions
encrypted secrets) and inject it as `FLASK_SECRET_KEY` at
deploy time. Never commit it to git.

For ephemeral / short-lived workers where session loss between
restarts is acceptable, generating at startup with `secrets`
is also reasonable:

```python
import secrets
app.config["SECRET_KEY"] = secrets.token_hex(32)
```

## What to do if it has already leaked

1. Rotate immediately — change the env var, redeploy. All
   existing sessions become invalid; users must log in again.
2. Audit logs for any signed token that survived the leak window
   (password-reset links, email-confirm links, share links).
   Treat them as compromised and re-issue.
3. Revoke long-lived `itsdangerous`-signed tokens by changing
   the salt as well as the key.

## How to suppress

A literal `SECRET_KEY` is almost never the right answer in
production. If you have a genuinely dev-only config file that
production never imports (a `tests/conftest.py` fixture, a local
`config_dev.py`), suppress per-line with reasoning:

```python
# rastray-ignore: RSTR-FLASK-002 — test fixture; never imported by app.py
app.config["SECRET_KEY"] = "test-only-secret"
```

## References

- [Flask — `SECRET_KEY` config value](https://flask.palletsprojects.com/en/latest/config/#SECRET_KEY)
- [itsdangerous — signing API](https://itsdangerous.palletsprojects.com/en/latest/)
- [OWASP A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-798 — Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-547 — Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
