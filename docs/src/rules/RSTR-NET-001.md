# RSTR-NET-001 — TLS verification disabled

## Summary

A Python HTTP request is made with `verify=False`. The
client will accept any TLS certificate, including expired,
self-signed, or attacker-presented ones. Traffic between
the client and the supposed server is now vulnerable to a
**man-in-the-middle** attack — the attacker can read and
modify everything, including auth tokens and request bodies.

## Severity

`High`.

## Languages

Python (`requests`, `httpx`, `urllib3` all accept the same
flag).

## How to fix it

**Remove the flag** — the default of `verify=True` is what
you want.

If you genuinely need a custom certificate authority (e.g.
your company's internal CA), pass the bundle path:

```python
response = requests.get('https://internal.example.com', verify='/etc/ssl/internal-ca.pem')
```

For testing against `localhost` with a self-signed cert,
create a real test certificate with `mkcert` instead — it
takes 30 seconds and means your test code looks like
production code.

`verify=False` is **never** the right answer in production.

## References

- [`requests` SSL Cert Verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [mkcert](https://github.com/FiloSottile/mkcert)
