# RSTR-XXE-001 — Python stdlib XML parsers

## Summary

Python's standard-library XML parsers (`xml.etree`,
`xml.sax`, `xml.dom.minidom`) resolve external entities by
default. An attacker can submit XML containing
`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
and the parser will fetch the local file (or any
`http://`-accessible URL) and embed it in the document.

This is **XML External Entity** injection (XXE) — local-file
disclosure, SSRF via entity URIs, and on some configurations
DoS via the [billion-laughs attack](https://en.wikipedia.org/wiki/Billion_laughs_attack).

## Severity

`High`.

## Languages

Python.

## How to fix it

Use [`defusedxml`](https://pypi.org/project/defusedxml/):

```python
import defusedxml.ElementTree as ET
tree = ET.fromstring(payload)
```

`defusedxml` is a drop-in replacement that hardens every
stdlib parser. It's the official recommendation in Python's
own documentation.

## References

- [Python docs: XML vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)
- [defusedxml on PyPI](https://pypi.org/project/defusedxml/)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [CWE-611: XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
