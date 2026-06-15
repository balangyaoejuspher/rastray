# RSTR-SEC-006 — Google API key (`AIza…`)

## Summary

A Google Cloud API key (`AIza` + 35 base62 chars) appears in the
repository. Depending on the key's restrictions, an attacker can call
any API the key was authorised for — Maps, Translate, Cloud Vision,
PaLM, etc. Most engineers set no restrictions, so the key is usable
from anywhere.

## Severity

`High`. Even rate-limited keys can drain a daily quota; unrestricted
keys to billable APIs can incur thousands of dollars in usage in
hours.

## Languages

Any scannable text file.

## What rastray flags

```js
const MAPS_KEY = "AIzaEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEAA";   // ← flagged
```

## What rastray deliberately does *not* flag

- Documentation placeholders with low entropy.

## How to fix it

1. **Restrict and rotate**: in the Google Cloud Console, set
   application restrictions (HTTP referrers for browser keys, IP
   range for server keys) and rotate the key.
2. Move the new key to environment / secret manager.
3. Rewrite git history.
4. Check Cloud Billing for the usage spike that suggests abuse.

For browser-side use cases (e.g. Maps embeds) the key is intended to
be public — set HTTP-referrer restrictions and the leak is mostly
inert. The rule still fires because the safe pattern is to inject
the key at build time from an environment variable so referrer
restrictions can be revisited in one place.

## References

- [Google Cloud: API keys best practices](https://cloud.google.com/docs/authentication/api-keys)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
