# RSTR-SSRF-001 — fetch/axios with request input

## Summary

A server-side HTTP request is built from request input that
the caller never validates. An attacker can substitute a URL
that points at internal infrastructure
(`http://localhost:6379`, `http://169.254.169.254` cloud
metadata, internal admin panels) and either exfiltrate the
response or use the server as a confused-deputy proxy.

This is **server-side request forgery** (SSRF), CWE-918.

## Severity

`High`. SSRF in cloud workloads can read IAM credentials
from the metadata endpoint, leading directly to privilege
escalation.

## Languages

JavaScript, TypeScript (and their JSX / TSX / .mjs / .cjs
variants).

## What rastray flags

The first argument of `fetch(...)`, `axios.get(...)`,
`axios.post(...)`, `axios.put(...)`, `axios.patch(...)`,
`axios.delete(...)`, `axios.head(...)`, `axios.options(...)`,
or `axios.request(...)` is a direct property access on
`req.body.*`, `req.query.*`, `req.params.*`, `req.cookies.*`,
or `req.headers.*`.

True-positive example:

```js
app.get('/proxy', async (req, res) => {
  const r = await fetch(req.body.url);   // ← flagged
  res.send(await r.text());
});
```

```js
const r = await axios.get(req.query.next);   // ← flagged
```

## What rastray deliberately does *not* flag

**Indirect flow** via a local variable. The rule requires
the request expression to appear *directly* in the sink:

```js
const url = req.body.url;
const r = await fetch(url);                  // ← not flagged
```

This is the same conservative scope used by every other
rastray security rule. Multi-step taint flow is what CodeQL
and Semgrep Pro do; rastray catches the common 80% where
the dangerous value is right there in the call.

**Literal URLs**:

```js
const r = await fetch('https://api.github.com/repos/x/y');   // ← not flagged
```

**Validated values**:

```js
const safe = new URL(req.body.url);
if (!ALLOWED_HOSTS.has(safe.hostname)) throw new Error('blocked');
const r = await fetch(safe);                  // ← not flagged
```

## Why the finding message looks the way it does

Every `RSTR-SSRF-001` finding interpolates the matched call:

> RSTR-SSRF-001: `fetch(req.body.url)` issues an HTTP request to a URL taken from request input — SSRF risk

If you have 50 SSRF findings in one report, all 50 messages
are distinguishable because each shows the exact call that
matched, not a generic template.

## How to fix it

**Option 1 — allow-list the host:**

```js
const ALLOWED_HOSTS = new Set([
  'api.example.com',
  'cdn.example.com',
]);

const target = new URL(req.body.url);
if (!ALLOWED_HOSTS.has(target.hostname)) {
  return res.status(400).send('host not allowed');
}
const r = await fetch(target);
```

**Option 2 — route through a hardened proxy** that strips
inbound URLs and only fetches from a known set of upstreams.

**Option 3 — eliminate the feature.** Most "fetch arbitrary
URL on behalf of the user" features can be replaced with a
client-side ``<iframe>`` or a server-side fetch from a
catalog rather than a free-form URL.

## How to suppress this finding

Only if the URL is genuinely safe — for example, a private
API where the caller is already authenticated and you've
sanitised the host against an allow-list inside a helper
the rule can't see across.

```js
// rastray-ignore: RSTR-SSRF-001
const r = await safeFetch(req.body.url);
```

Or project-wide in `.rastray.toml`:

```toml
[rules]
"RSTR-SSRF-001" = { severity = "low" }   # downgrade to informational
```

## References

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger: SSRF attacks](https://portswigger.net/web-security/ssrf)
- [HackerOne: Hunting for SSRF bugs](https://www.hackerone.com/blog/Server-Side-Request-Forgery)
- [Cloud metadata SSRF: AWS Capital One incident write-up](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/)
