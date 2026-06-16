# Summary

- [Introduction](./introduction.md)
- [Quickstart](./quickstart.md)
- [How to read these pages](./how-to-read.md)

# Benchmarks

- [Methodology](./benchmarks/methodology.md)
- [Summary table](./benchmarks/summary.md)
- [OWASP Juice Shop](./benchmarks/juice-shop.md)
- [OWASP NodeGoat](./benchmarks/nodegoat.md)
- [DVWA](./benchmarks/dvwa.md)
- [OWASP RailsGoat](./benchmarks/railsgoat.md)
- [WebGoat](./benchmarks/webgoat.md)
- [django-DefectDojo](./benchmarks/django-defectdojo.md)

# Secrets in source

- [RSTR-SEC-001 — hard-coded credential pattern](./rules/RSTR-SEC-001.md)
- [RSTR-SEC-002 — GitHub personal access token](./rules/RSTR-SEC-002.md)
- [RSTR-SEC-003 — GitHub fine-grained PAT](./rules/RSTR-SEC-003.md)
- [RSTR-SEC-004 — Slack bot token](./rules/RSTR-SEC-004.md)
- [RSTR-SEC-005 — Stripe live secret key](./rules/RSTR-SEC-005.md)
- [RSTR-SEC-006 — Google API key](./rules/RSTR-SEC-006.md)
- [RSTR-SEC-007 — PEM private key](./rules/RSTR-SEC-007.md)
- [RSTR-SEC-008 — npm access token](./rules/RSTR-SEC-008.md)

# Broken cryptography

- [RSTR-CRY-001 — MD5 used for hashing](./rules/RSTR-CRY-001.md)
- [RSTR-CRY-002 — SHA-1 used for hashing](./rules/RSTR-CRY-002.md)
- [RSTR-CRY-003 — DES / 3DES cipher](./rules/RSTR-CRY-003.md)
- [RSTR-CRY-004 — ECB cipher mode](./rules/RSTR-CRY-004.md)
- [RSTR-CRY-005 — Math.random() used for security](./rules/RSTR-CRY-005.md)
- [RSTR-CRY-006 — Python random / Go math/rand for security](./rules/RSTR-CRY-006.md)
- [RSTR-CRY-007 — Rust rand::thread_rng() for security](./rules/RSTR-CRY-007.md)

# Injection

- [RSTR-INJ-001 — SQL injection via f-string / template literal](./rules/RSTR-INJ-001.md)
- [RSTR-INJ-002 — Python subprocess(shell=True) / os.system](./rules/RSTR-INJ-002.md)
- [RSTR-INJ-003 — eval / exec / new Function](./rules/RSTR-INJ-003.md)
- [RSTR-INJ-004 — Node child_process.exec with template literal](./rules/RSTR-INJ-004.md)
- [RSTR-INJ-005 — Go exec.Command with sh -c](./rules/RSTR-INJ-005.md)
- [RSTR-INJ-006 — PHP SQL query built from request superglobal](./rules/RSTR-INJ-006.md)
- [RSTR-INJ-007 — PHP command exec on request superglobal](./rules/RSTR-INJ-007.md)
- [RSTR-INJ-008 — Rails .where with string interpolation of params](./rules/RSTR-INJ-008.md)
- [RSTR-INJ-009 — Rails params[...].constantize / classify](./rules/RSTR-INJ-009.md)
- [RSTR-INJ-010 — Rails render inline: / text: with params interpolation](./rules/RSTR-INJ-010.md)
- [RSTR-INJ-011 — C system / popen / exec* with non-literal argument](./rules/RSTR-INJ-011.md)

# Memory safety (C / C++)

- [RSTR-MEM-001 — strcpy / strcat / gets / sprintf](./rules/RSTR-MEM-001.md)
- [RSTR-MEM-002 — scanf with unbounded %s](./rules/RSTR-MEM-002.md)
- [RSTR-MEM-003 — alloca on attacker-controlled size](./rules/RSTR-MEM-003.md)
- [RSTR-MEM-004 — memcpy / memmove with strlen length](./rules/RSTR-MEM-004.md)
- [RSTR-MEM-005 — raw new outside a smart pointer](./rules/RSTR-MEM-005.md)

# Server-side request forgery

- [RSTR-SSRF-001 — Node fetch / axios with request input](./rules/RSTR-SSRF-001.md)
- [RSTR-SSRF-002 — Node http / https with request input](./rules/RSTR-SSRF-002.md)
- [RSTR-SSRF-003 — Python requests / urlopen with request input](./rules/RSTR-SSRF-003.md)
- [RSTR-SSRF-004 — Go http.Get / http.NewRequest with request input](./rules/RSTR-SSRF-004.md)

# Cross-site scripting

- [RSTR-XSS-001 — reflected XSS via res.send/res.end/res.write](./rules/RSTR-XSS-001.md)
- [RSTR-XSS-002 — DOM-based XSS via innerHTML/outerHTML](./rules/RSTR-XSS-002.md)
- [RSTR-XSS-003 — document.write with DOM data](./rules/RSTR-XSS-003.md)
- [RSTR-XSS-004 — Flask Markup / direct return of request input](./rules/RSTR-XSS-004.md)
- [RSTR-XSS-005 — Go HTTP response writes with request input](./rules/RSTR-XSS-005.md)
- [RSTR-XSS-006 — PHP echo / print of request superglobal](./rules/RSTR-XSS-006.md)

# JSON-Web-Token misuse

- [RSTR-JWT-001 — alg:none or wildcard algorithms accepted](./rules/RSTR-JWT-001.md)
- [RSTR-JWT-002 — JWT verification disabled](./rules/RSTR-JWT-002.md)
- [RSTR-JWT-003 — hardcoded JWT secret in source](./rules/RSTR-JWT-003.md)
- [RSTR-JWT-004 — verify without explicit algorithms list](./rules/RSTR-JWT-004.md)
- [RSTR-JWT-005 — Go jwt.Parse keyfunc without method check](./rules/RSTR-JWT-005.md)

# Open redirect

- [RSTR-RDR-001 — Express res.redirect(req.x)](./rules/RSTR-RDR-001.md)
- [RSTR-RDR-002 — Flask / Django redirect with request input](./rules/RSTR-RDR-002.md)
- [RSTR-RDR-003 — Go http.Redirect with request input](./rules/RSTR-RDR-003.md)
- [RSTR-RDR-004 — Rails redirect_to params[...]](./rules/RSTR-RDR-004.md)

# Server-side template injection

- [RSTR-SSTI-001 — Python render_template_string / Template(req.x)](./rules/RSTR-SSTI-001.md)
- [RSTR-SSTI-002 — Node template compile from request input](./rules/RSTR-SSTI-002.md)

# XML external entity

- [RSTR-XXE-001 — Python stdlib XML parsers](./rules/RSTR-XXE-001.md)
- [RSTR-XXE-002 — lxml XMLParser(resolve_entities=True)](./rules/RSTR-XXE-002.md)
- [RSTR-XXE-003 — libxmljs parseXml with noent: true](./rules/RSTR-XXE-003.md)
- [RSTR-XXE-004 — xml2js permissive parser options](./rules/RSTR-XXE-004.md)
- [RSTR-XXE-005 — Java XML factory without entity hardening](./rules/RSTR-XXE-005.md)

# NoSQL injection

- [RSTR-NOSQLI-001 — Mongo find/update with req.body object](./rules/RSTR-NOSQLI-001.md)
- [RSTR-NOSQLI-002 — Mongo $where with request input](./rules/RSTR-NOSQLI-002.md)
- [RSTR-NOSQLI-003 — PyMongo filter from request.*](./rules/RSTR-NOSQLI-003.md)

# Deserialization

- [RSTR-DES-001 — Python pickle.loads on untrusted input](./rules/RSTR-DES-001.md)
- [RSTR-DES-002 — Python yaml.load without SafeLoader](./rules/RSTR-DES-002.md)
- [RSTR-DES-003 — Python marshal.loads on untrusted input](./rules/RSTR-DES-003.md)
- [RSTR-DES-004 — Node node-serialize unserialize](./rules/RSTR-DES-004.md)
- [RSTR-DES-005 — Ruby Marshal.load](./rules/RSTR-DES-005.md)
- [RSTR-DES-006 — Java ObjectInputStream.readObject](./rules/RSTR-DES-006.md)
- [RSTR-DES-007 — PHP unserialize](./rules/RSTR-DES-007.md)

# Path traversal

- [RSTR-PTH-001 — Flask send_file(request.*)](./rules/RSTR-PTH-001.md)
- [RSTR-PTH-002 — Express sendFile / fs read with request input](./rules/RSTR-PTH-002.md)
- [RSTR-PTH-003 — Java new File(servletRequest...)](./rules/RSTR-PTH-003.md)
- [RSTR-PTH-004 — literal ../../ in source](./rules/RSTR-PTH-004.md)
- [RSTR-PTH-005 — PHP include/require from request superglobal](./rules/RSTR-PTH-005.md)
- [RSTR-PTH-006 — PHP file API on request superglobal](./rules/RSTR-PTH-006.md)

# Web-app configuration

- [RSTR-COOKIE-001 — cookie without secure: true](./rules/RSTR-COOKIE-001.md)
- [RSTR-COOKIE-002 — cookie without httpOnly: true](./rules/RSTR-COOKIE-002.md)
- [RSTR-COOKIE-003 — cookie with sameSite: 'none'](./rules/RSTR-COOKIE-003.md)
- [RSTR-CORS-001 — cors origin:true|* with credentials:true](./rules/RSTR-CORS-001.md)
- [RSTR-CORS-002 — manual ACAO: * with credentials](./rules/RSTR-CORS-002.md)
- [RSTR-CSRF-001 — Flask WTF_CSRF_ENABLED disabled](./rules/RSTR-CSRF-001.md)
- [RSTR-CSRF-002 — Django @csrf_exempt](./rules/RSTR-CSRF-002.md)

# ORM mass-assignment

- [RSTR-ORM-001 — Node ORM Model.create(req.body)](./rules/RSTR-ORM-001.md)
- [RSTR-ORM-002 — Django ORM create with **request.POST](./rules/RSTR-ORM-002.md)
- [RSTR-ORM-003 — Rails create / update with raw params](./rules/RSTR-ORM-003.md)
- [RSTR-ORM-004 — raw SQL template literal](./rules/RSTR-ORM-004.md)
- [RSTR-ORM-005 — Rails params.require(:x).permit! (open permit)](./rules/RSTR-ORM-005.md)

# LDAP injection

- [RSTR-LDAP-001 — ldapjs search with template-literal filter](./rules/RSTR-LDAP-001.md)
- [RSTR-LDAP-002 — Python LDAP filter built with f-string](./rules/RSTR-LDAP-002.md)

# Regular expressions

- [RSTR-REDOS-001 — nested quantifier catastrophic backtracking](./rules/RSTR-REDOS-001.md)

# Network

- [RSTR-NET-001 — TLS verification disabled](./rules/RSTR-NET-001.md)
- [RSTR-NET-002 — Python SSL context with verification disabled](./rules/RSTR-NET-002.md)
- [RSTR-NET-003 — Wildcard CORS with credentials](./rules/RSTR-NET-003.md)
- [RSTR-NET-004 — cookie httpOnly: false (network variant)](./rules/RSTR-NET-004.md)

# CI / GitHub Actions

- [RSTR-GHA-001 — pull_request_target + PR-head checkout](./rules/RSTR-GHA-001.md)
- [RSTR-GHA-002 — action pinned by floating tag](./rules/RSTR-GHA-002.md)
- [RSTR-GHA-003 — github.event.* interpolated into run:](./rules/RSTR-GHA-003.md)
- [RSTR-GHA-005 — checkout with persist-credentials: true](./rules/RSTR-GHA-005.md)

# Containers / Infrastructure-as-Code

- [RSTR-IAC-001 — FROM image:latest](./rules/RSTR-IAC-001.md)
- [RSTR-IAC-002 — USER root in runtime stage](./rules/RSTR-IAC-002.md)
- [RSTR-IAC-003 — ADD with remote URL](./rules/RSTR-IAC-003.md)
- [RSTR-IAC-005 — chmod 777](./rules/RSTR-IAC-005.md)
- [RSTR-IAC-006 — curl | sh](./rules/RSTR-IAC-006.md)
- [RSTR-IAC-007 — privileged container](./rules/RSTR-IAC-007.md)
- [RSTR-IAC-008 — host namespace shared](./rules/RSTR-IAC-008.md)
- [RSTR-IAC-009 — public S3 bucket ACL](./rules/RSTR-IAC-009.md)
- [RSTR-IAC-010 — open ingress cidr 0.0.0.0/0](./rules/RSTR-IAC-010.md)
- [RSTR-IAC-011 — publicly accessible database](./rules/RSTR-IAC-011.md)

# Performance — Rust

- [RSTR-PERF-001 — format! accumulator in a loop](./rules/RSTR-PERF-001.md)
- [RSTR-PERF-002 — for x in xs.clone()](./rules/RSTR-PERF-002.md)

# Performance — JavaScript / TypeScript

- [RSTR-PERF-101 — await inside a loop](./rules/RSTR-PERF-101.md)
- [RSTR-PERF-102 — new Date() inside a loop](./rules/RSTR-PERF-102.md)

# Performance — Python

- [RSTR-PERF-201 — string += inside a loop](./rules/RSTR-PERF-201.md)
- [RSTR-PERF-202 — time.sleep() inside an async def](./rules/RSTR-PERF-202.md)

# Performance — Go

- [RSTR-PERF-301 — defer inside a for loop](./rules/RSTR-PERF-301.md)
- [RSTR-PERF-302 — fmt.Sprintf inside a for loop](./rules/RSTR-PERF-302.md)
