# RSTR-XXE-002 — lxml `XMLParser(resolve_entities=True)`

## Summary

`lxml.etree.XMLParser` is constructed with `resolve_entities=True` (the
default), so external entities embedded in the parsed XML are resolved.
A malicious document can read local files (`file:///etc/passwd`) or
make outbound HTTP requests (SSRF) from the parser process.

## Severity

`High`.

## Languages

Python.

## What rastray flags

```python
from lxml import etree

parser = etree.XMLParser(resolve_entities=True)    # ← flagged
tree   = etree.fromstring(payload, parser)
```

```python
parser = etree.XMLParser()                          # ← flagged (defaults to True)
```

## What rastray deliberately does *not* flag

- `etree.XMLParser(resolve_entities=False, no_network=True)`.
- `defusedxml.lxml.parse(...)` / `fromstring(...)`.

## How to fix it

Either harden the parser:

```python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    huge_tree=False,
    dtd_validation=False,
    load_dtd=False,
)
tree = etree.fromstring(payload, parser)
```

Or, easier, use `defusedxml.lxml`:

```python
from defusedxml.lxml import fromstring
tree = fromstring(payload)
```

`defusedxml` is the OWASP-recommended drop-in: it disables every
XXE-relevant feature by default and the API mirrors stdlib lxml.

## References

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#python)
- [`defusedxml` README](https://pypi.org/project/defusedxml/)
- [CWE-611](https://cwe.mitre.org/data/definitions/611.html)
