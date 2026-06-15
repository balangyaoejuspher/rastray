# RSTR-XXE-004 — `xml2js` permissive parser options

## Summary

`xml2js` is configured with `explicitArray: false` as the only safety
toggle — entity expansion is still on by default. The application is
exposed to billion-laughs DoS and to entity-based data exfiltration
when the upstream library version permits it.

This rule is intentionally narrower than the lxml / libxmljs ones: it
flags the "I tweaked parser options for convenience but didn't think
about security" pattern.

## Severity

`Medium`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
const parser = new xml2js.Parser({ explicitArray: false }); // ← flagged
parser.parseString(payload, cb);
```

## What rastray deliberately does *not* flag

- `new xml2js.Parser()` with default options.
- `Parser` constructions where `explicitCharkey: true` and explicit
  entity-handling options are also set.

## How to fix it

Switch to a parser with safer defaults (`fast-xml-parser`, which
disables entity expansion) **or** validate the input before parsing:

```js
import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
  ignoreAttributes: false,
  processEntities: false,        // explicitly off
});
const json = parser.parse(payload);
```

If you must keep `xml2js`, add an upstream size/depth limit (HTTP body
limit, a regex-based reject for `<!DOCTYPE`/`<!ENTITY` blocks) and
suppress with a comment noting the mitigation.

## References

- [`fast-xml-parser` docs](https://github.com/NaturalIntelligence/fast-xml-parser#readme)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [CWE-776: Improper Restriction of Recursive Entity References (Billion Laughs)](https://cwe.mitre.org/data/definitions/776.html)
