# RSTR-DJANGO-002 — settings file declares `ALLOWED_HOSTS = ['*']`

## Summary

A Django settings module sets `ALLOWED_HOSTS = ['*']` (wildcard).
Django will accept any value the caller puts in the HTTP `Host`
header and treat it as the canonical hostname for that request.
That unlocks a documented attack class:

- **Cache poisoning** — `Host: attacker.com` plus a request that
  hits an upstream cache; subsequent users get the poisoned
  response (`canonical_url` rendered from the attacker's host).
- **Password-reset link poisoning** — Django's password-reset
  email template builds the reset URL from `request.get_host()`,
  which echoes the attacker-supplied Host. Sending a reset
  request with `Host: attacker.com` mails the victim a reset
  link that posts the new password to the attacker.
- **SSRF via Host-relative URLs** — any internal job that uses
  `reverse()` plus a host the request reported can be tricked
  into hitting attacker infrastructure.

Wildcard `ALLOWED_HOSTS` is never the right answer in production.

## Severity

`Critical`.

## Languages

Python (`.py`) inside a project whose Python manifest
(`pyproject.toml`, `requirements.txt`, `Pipfile`, `poetry.lock`,
or `uv.lock`) declares `django`.

## What rastray flags

```python
# settings.py
INSTALLED_APPS = [...]
MIDDLEWARE = [...]
ALLOWED_HOSTS = ['*']                            # ← flagged
```

Double-quoted form is also flagged:

```python
ALLOWED_HOSTS = ["*"]                            # ← flagged
```

## What rastray deliberately does *not* flag

Explicit host lists:

```python
ALLOWED_HOSTS = ['app.example.com', 'admin.example.com']
```

Env-driven lists:

```python
ALLOWED_HOSTS = os.environ['DJANGO_ALLOWED_HOSTS'].split(',')
```

Subdomain wildcards under a real domain (a Django feature):

```python
ALLOWED_HOSTS = ['.example.com']      # *.example.com — scoped to your domain only
```

`ALLOWED_HOSTS = []` (empty) — Django refuses every Host header,
which is restrictive but not a security bug.

Files that aren't Django settings modules (no `INSTALLED_APPS`
or `MIDDLEWARE` declaration) are not flagged even when their
basename is `settings.py`.

## How to fix it

Set the value to your real production domains:

```python
ALLOWED_HOSTS = ['app.example.com', 'admin.example.com']
```

Or drive from the environment when the list varies per
deployment:

```python
ALLOWED_HOSTS = os.environ['DJANGO_ALLOWED_HOSTS'].split(',')
```

If you run behind a load balancer that terminates TLS and you
need to accept multiple subdomains, use Django's leading-dot
shorthand which means "this domain or any subdomain":

```python
ALLOWED_HOSTS = ['.example.com']
```

## How to suppress

A legitimate use of wildcard `ALLOWED_HOSTS` is genuinely rare —
maybe a quickstart Docker image meant only for `localhost`
demos. If you have one, suppress with reasoning:

```python
# rastray-ignore: RSTR-DJANGO-002 — demo container, never exposed beyond localhost
ALLOWED_HOSTS = ['*']
```

## References

- [Django — `ALLOWED_HOSTS` setting](https://docs.djangoproject.com/en/stable/ref/settings/#allowed-hosts)
- [Django — Host header validation](https://docs.djangoproject.com/en/stable/topics/security/#host-header-validation)
- [OWASP — HTTP Host header attacks](https://owasp.org/www-community/attacks/Host_Header_Injection)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
