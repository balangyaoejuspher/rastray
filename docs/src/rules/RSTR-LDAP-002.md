# RSTR-LDAP-002 — Python LDAP filter built with f-string

## Summary

A Python LDAP search builds the filter string from request input via
an f-string or `.format(...)`. An attacker submitting `*)(uid=*` (or
similar metacharacter payloads) bypasses authentication or enumerates
the directory.

This is the Python counterpart of [`RSTR-LDAP-001`](./RSTR-LDAP-001.md).

## Severity

`High`.

## Languages

Python (`ldap3`, `python-ldap`).

## What rastray flags

```python
conn.search(base_dn, f'(uid={user})', search_scope=SUBTREE)   # ← flagged
```

```python
conn.search_s(base_dn, ldap.SCOPE_SUBTREE,
              '(uid={})'.format(user))                         # ← flagged
```

## What rastray deliberately does *not* flag

- Filters built from literal strings.
- Filters built with `ldap3.utils.conv.escape_filter_chars(...)` first.
- Filters built from a parsed/validated identifier (e.g. a UUID).

## How to fix it

Escape the input with the library's escape helper:

```python
from ldap3.utils.conv import escape_filter_chars

conn.search(base_dn,
            f'(uid={escape_filter_chars(user)})',
            search_scope=SUBTREE)
```

For `python-ldap`:

```python
import ldap.filter
filter_str = ldap.filter.filter_format('(uid=%s)', [user])
conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```

`filter_format` parametrises like a prepared statement — it's the
LDAP equivalent of `?` placeholders.

## References

- [`ldap3` filter escaping docs](https://ldap3.readthedocs.io/en/latest/standardoperations.html)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [CWE-90](https://cwe.mitre.org/data/definitions/90.html)
