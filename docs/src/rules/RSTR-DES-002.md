# RSTR-DES-002 — Python `yaml.load` without `SafeLoader`

## Summary

PyYAML's `yaml.load(stream)` (with no explicit `Loader`) constructs
arbitrary Python objects from the document — including ones whose
`__reduce__` runs `os.system('rm -rf /')`. The CVE-2017-18342 advisory
made `yaml.load` issue a warning, and recent PyYAML releases require
an explicit loader, but legacy code still triggers the trap.

## Severity

`High`.

## Languages

Python.

## What rastray flags

```python
import yaml
cfg = yaml.load(open('config.yaml'))               # ← flagged
cfg = yaml.load(request.data)                      # ← flagged
```

## What rastray deliberately does *not* flag

- `yaml.safe_load(...)`.
- `yaml.load(stream, Loader=yaml.SafeLoader)`.
- `yaml.load(stream, Loader=yaml.CSafeLoader)`.

## How to fix it

`yaml.safe_load` is a drop-in replacement that returns only Python
primitives (dicts, lists, strings, ints, floats, bools, None):

```python
import yaml
cfg = yaml.safe_load(open('config.yaml'))
```

If the YAML document is supposed to encode richer types (sets,
ordered dicts), define a custom SafeLoader subclass that explicitly
registers only the constructors you want. Never reach for
`FullLoader` or `UnsafeLoader` on untrusted input.

`rastray --fix --yes` auto-rewrites `yaml.load(x)` → `yaml.safe_load(x)`.

## References

- [PyYAML — `yaml.load` warning](https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml)
- [CVE-2017-18342](https://nvd.nist.gov/vuln/detail/CVE-2017-18342)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
