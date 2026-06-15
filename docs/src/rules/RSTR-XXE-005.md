# RSTR-XXE-005 — Java XML factory without entity hardening

## Summary

`DocumentBuilderFactory`, `SAXParserFactory`, or `XMLInputFactory` is
constructed without disabling external entities and DTD processing.
The defaults vary by JDK version and parser implementation; the OWASP
guidance is to set the hardening features explicitly so the code is
safe regardless of where it runs.

## Severity

`High`.

## Languages

Java.

## What rastray flags

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); // ← flagged
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(input);
```

```java
SAXParserFactory spf = SAXParserFactory.newInstance();             // ← flagged
SAXParser sp = spf.newSAXParser();
```

```java
XMLInputFactory xif = XMLInputFactory.newInstance();               // ← flagged
```

## What rastray deliberately does *not* flag

- Factories where every hardening feature (see below) is set.
- `XMLConstants.FEATURE_SECURE_PROCESSING` enabled *and* DTD/entity
  features explicitly disabled.

## How to fix it

Apply OWASP's hardening recipe before parsing:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
```

For `SAXParserFactory`, set the same `disallow-doctype-decl` feature.
For `XMLInputFactory`:

```java
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
```

If your project already wraps factory construction in a helper, run
`rastray` against just the helper and suppress callers.

## References

- [OWASP XXE Prevention Cheat Sheet — Java](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java)
- [CWE-611](https://cwe.mitre.org/data/definitions/611.html)
