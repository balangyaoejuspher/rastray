# RSTR-AXUM-001 — CORS `Any` origin combined with `allow_credentials(true)`

## Summary

An Axum service builds a `tower_http::cors::CorsLayer` with both
`.allow_origin(Any)` (wildcard origin) and
`.allow_credentials(true)`. The combination is forbidden by the
CORS specification — browsers silently strip cookies and the
`Authorization` header on cross-origin requests when the server
echoes back `Access-Control-Allow-Origin: *` with credentials —
and indicates the team intended to allow cross-origin authenticated
requests from anywhere, which defeats CSRF protection entirely.

Either the credentials path is broken in production (because
browsers refuse to forward cookies under wildcard origin) or the
service is deliberately accepting authenticated requests from
arbitrary origins. Both interpretations are configuration bugs.

## Severity

`High`.

## Languages

Rust (`.rs`) inside a project whose `Cargo.toml` declares `axum`.

## What rastray flags

```rust
use tower_http::cors::{Any, CorsLayer};

let layer = CorsLayer::new()
    .allow_origin(Any)              // ← flagged
    .allow_credentials(true)
    .allow_methods([axum::http::Method::GET, axum::http::Method::POST]);
```

The qualified form is also flagged:

```rust
let layer = CorsLayer::new()
    .allow_origin(tower_http::cors::Any)   // ← flagged
    .allow_credentials(true);
```

## What rastray deliberately does *not* flag

`Any` without credentials (a sensible config for fully-public
read APIs):

```rust
let layer = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods([axum::http::Method::GET]);
```

Explicit origin allow-list with credentials (the secure shape):

```rust
let layer = CorsLayer::new()
    .allow_origin([
        "https://app.example.com".parse().unwrap(),
        "https://admin.example.com".parse().unwrap(),
    ])
    .allow_credentials(true);
```

`AllowOrigin::predicate(...)` builders (the runtime origin check
form) — too dynamic to assert anything statically about.

## How to fix it

Decide which side of the trade-off you want:

**If the API is public read-only** — drop credentials:

```rust
let layer = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods([axum::http::Method::GET]);
```

**If the API needs authenticated cross-origin requests** — replace
`Any` with an explicit allow-list of origins you control:

```rust
let layer = CorsLayer::new()
    .allow_origin([
        "https://app.example.com".parse().unwrap(),
    ])
    .allow_credentials(true)
    .allow_methods([axum::http::Method::POST, axum::http::Method::PUT]);
```

If the allow-list needs to be dynamic (e.g. per-tenant subdomains),
use `AllowOrigin::predicate(|origin, _req| { ... })` and validate
the origin against your tenant directory before returning `true`.

## How to suppress

If you have a deliberate dev-only configuration that must keep
both settings (e.g. for a public sandbox), suppress at the
`.allow_origin(Any)` line:

```rust
// rastray-ignore: RSTR-AXUM-001 — public sandbox; no real user data behind this layer
let layer = CorsLayer::new()
    .allow_origin(Any)
    .allow_credentials(true);
```

## References

- [CORS specification — Credentials and wildcards](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)
- [tower-http CorsLayer documentation](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html)
- [OWASP A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-942 — Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
