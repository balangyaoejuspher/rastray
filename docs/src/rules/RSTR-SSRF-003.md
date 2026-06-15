# RSTR-SSRF-003 — Python `requests` / `urlopen` with request input

## Summary

Python equivalent of [`RSTR-SSRF-001`](./RSTR-SSRF-001.md). The
application performs a server-side HTTP call where the URL is sourced
directly from request attributes.

## Severity

`High`. In cloud workloads, an attacker can read the IAM-role metadata
endpoint and pivot to full account compromise.

## Languages

Python.

## What rastray flags

`requests.get` / `requests.post` / `requests.put` / `requests.patch` /
`requests.delete` / `requests.head` / `requests.options` / `requests.request`,
plus `urllib.request.urlopen`, when the URL is `request.args[...]`,
`request.form[...]`, `request.json[...]`, `request.values[...]`,
`request.GET[...]`, `request.POST[...]`, or `request.data[...]`:

```python
@app.route('/proxy')
def proxy():
    return requests.get(request.args['url']).text   # ← flagged
```

```python
def view(request):
    body = urlopen(request.GET['next']).read()      # ← flagged
```

## What rastray deliberately does *not* flag

- Literal URLs.
- URLs assigned to a local first, then passed to `requests` — same
  one-step taint scope as the rest of rastray.
- `requests.Session()` configured with a fixed `base_url` (rare in
  practice but appears in some clients).

## How to fix it

Validate the target host before making the outbound call:

```python
from urllib.parse import urlparse
import ipaddress, socket

ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}

def fetch_safe(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('only http(s) allowed')
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError('host not allow-listed')
    # belt-and-suspenders: resolve and reject private IPs
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError('private destination')
    return requests.get(url, timeout=5, allow_redirects=False).content
```

`allow_redirects=False` matters — without it, an allow-listed host can
redirect the request into the metadata endpoint.

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Capital One SSRF write-up](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/)
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
