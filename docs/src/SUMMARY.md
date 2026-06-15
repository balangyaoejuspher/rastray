# Summary

- [Introduction](./introduction.md)
- [How to read these pages](./how-to-read.md)

# Secrets

- [RSTR-SEC-001 — hard-coded credential pattern](./rules/RSTR-SEC-001.md)

# Broken cryptography

- [RSTR-CRY-001 — MD5 used for hashing](./rules/RSTR-CRY-001.md)
- [RSTR-CRY-002 — SHA-1 used for hashing](./rules/RSTR-CRY-002.md)

# Injection

- [RSTR-INJ-001 — SQL injection via f-string / template literal](./rules/RSTR-INJ-001.md)

# Server-side request forgery

- [RSTR-SSRF-001 — fetch/axios with request input](./rules/RSTR-SSRF-001.md)

# Cross-site scripting

- [RSTR-XSS-001 — reflected XSS via res.send/res.end/res.write](./rules/RSTR-XSS-001.md)
- [RSTR-XSS-002 — DOM-based XSS via innerHTML/outerHTML](./rules/RSTR-XSS-002.md)

# JSON-Web-Token misuse

- [RSTR-JWT-001 — alg:none or wildcard algorithms accepted](./rules/RSTR-JWT-001.md)
- [RSTR-JWT-004 — verify without explicit algorithms list](./rules/RSTR-JWT-004.md)

# Open redirect

- [RSTR-RDR-001 — Express res.redirect(req.x)](./rules/RSTR-RDR-001.md)

# Server-side template injection

- [RSTR-SSTI-001 — Python render_template_string / Template(req.x)](./rules/RSTR-SSTI-001.md)

# XML external entity

- [RSTR-XXE-001 — Python stdlib XML parsers](./rules/RSTR-XXE-001.md)

# NoSQL injection

- [RSTR-NOSQLI-001 — Mongo find/update with req.body object](./rules/RSTR-NOSQLI-001.md)
- [RSTR-NOSQLI-002 — Mongo $where with request input](./rules/RSTR-NOSQLI-002.md)

# Web-app configuration

- [RSTR-CORS-001 — cors origin:true|* with credentials:true](./rules/RSTR-CORS-001.md)
- [RSTR-CSRF-001 — Flask WTF_CSRF_ENABLED disabled](./rules/RSTR-CSRF-001.md)

# ORM mass-assignment

- [RSTR-ORM-001 — Node ORM Model.create(req.body)](./rules/RSTR-ORM-001.md)
- [RSTR-ORM-004 — raw SQL template literal](./rules/RSTR-ORM-004.md)

# LDAP injection

- [RSTR-LDAP-001 — ldapjs search with template-literal filter](./rules/RSTR-LDAP-001.md)

# Regular expressions

- [RSTR-REDOS-001 — nested quantifier catastrophic backtracking](./rules/RSTR-REDOS-001.md)

# Network

- [RSTR-NET-001 — TLS verification disabled](./rules/RSTR-NET-001.md)
