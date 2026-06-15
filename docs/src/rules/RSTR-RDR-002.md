# RSTR-RDR-002 — Flask / Django redirect with request input

## Summary

A Python web handler redirects the browser to a URL taken directly
from request arguments. An attacker can craft a link such as
`https://yoursite/login?next=https://phish.example` — the victim sees
a trusted-looking link, clicks, and lands on the attacker's page after
the redirect.

## Severity

`Medium`. Open-redirects amplify phishing and frequently chain into
OAuth-flow takeovers when the redirect target receives a token.

## Languages

Python (Flask, Django).

## What rastray flags

```python
@app.route('/post-login')
def post_login():
    return redirect(request.args['next'])           # ← flagged
```

```python
def view(request):
    return HttpResponseRedirect(request.GET['next'])  # ← flagged
```

## What rastray deliberately does *not* flag

- `redirect(url_for('some_view'))` (named URLs).
- Redirects to literal strings.
- Redirects passed through `urlsafe_allowed_hosts(...)` or any helper
  that the rule cannot resolve.

## How to fix it

Validate the redirect target against an allow-list (relative paths or
trusted hosts):

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {'app.example.com', 'admin.example.com'}

def safe_redirect_target(raw: str) -> str:
    parsed = urlparse(raw)
    if not parsed.netloc:
        return raw                       # relative path — safe
    if parsed.netloc in ALLOWED_HOSTS:
        return raw                       # trusted external host
    return '/'                           # fall back to home

@app.route('/post-login')
def post_login():
    return redirect(safe_redirect_target(request.args.get('next', '/')))
```

Django ships an equivalent helper out of the box —
`django.utils.http.url_has_allowed_host_and_scheme` — use it on every
`next=` parameter.

## References

- [Django `url_has_allowed_host_and_scheme`](https://docs.djangoproject.com/en/stable/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601](https://cwe.mitre.org/data/definitions/601.html)
