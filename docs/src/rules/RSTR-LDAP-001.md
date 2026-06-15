# RSTR-LDAP-001 — ldapjs search with template-literal filter

## Summary

An LDAP `search` call is given a filter built by string
interpolation: `` `(uid=${userInput})` ``. The LDAP filter
grammar has metacharacters (`*`, `(`, `)`, `\`, `NUL`) that
let an attacker rewrite the filter:

- ``*)(uid=*`` matches everything;
- ``*)(|(role=admin)`` enumerates admins;
- ``*)(uid=*))(|(&(uid=*`` opens the door to filter-tree
  injection.

This is the LDAP cousin of SQL injection.

## Severity

`High`.

## Languages

JavaScript / TypeScript.

## How to fix it

Escape every interpolated value with the LDAP filter
character escape:

```js
import ldapEscape from 'ldap-escape';
client.search('dc=example,dc=com', {
  filter: `(uid=${ldapEscape.filter`${userInput}`})`,
});
```

Or build the filter from a structured object via
`ldapjs.parseFilter` so there's no string to interpolate
into at all.

## References

- [CWE-90: LDAP Injection](https://cwe.mitre.org/data/definitions/90.html)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [RFC 4515: LDAP Search Filter syntax](https://www.rfc-editor.org/rfc/rfc4515)
