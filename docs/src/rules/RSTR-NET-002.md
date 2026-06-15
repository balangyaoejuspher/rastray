# RSTR-NET-002 — Python SSL context with verification disabled

## Summary

A Python `ssl` context is configured with `check_hostname = False`,
`verify_mode = ssl.CERT_NONE`, or both — turning off the parts of
TLS that prevent MITM. The connection is encrypted but
unauthenticated; any on-path attacker can impersonate the server.

## Severity

`High`.

## Languages

Python.

## What rastray flags

```python
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False                          # ← flagged
ctx.verify_mode = ssl.CERT_NONE                     # ← flagged
```

```python
ssl._create_default_https_context = ssl._create_unverified_context  # ← flagged
```

## What rastray deliberately does *not* flag

- `ssl.create_default_context()` with no overrides.
- Test code that explicitly pins a self-signed cert via `load_verify_locations`.

## How to fix it

Default to verification on and supply a trust store if you must
override:

```python
import ssl

ctx = ssl.create_default_context()  # check_hostname + CERT_REQUIRED on by default
# Optionally pin to an internal CA:
ctx.load_verify_locations(cafile='/etc/ssl/internal-ca.crt')

with socket.create_connection((host, 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        tls.sendall(payload)
```

For `requests`, the equivalent flag is `verify=False` — the matching
rule is `RSTR-NET-001`.

## References

- [Python `ssl` docs — security considerations](https://docs.python.org/3/library/ssl.html#ssl-security)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
