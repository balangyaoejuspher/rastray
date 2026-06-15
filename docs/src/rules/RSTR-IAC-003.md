# RSTR-IAC-003 — Dockerfile `ADD <url>`

## Summary

Dockerfile `ADD` with a remote URL has two specific weaknesses
relative to `RUN curl`:

1. The downloaded blob has **no integrity check** — no checksum, no
   signature. If the upstream is compromised or DNS is poisoned, the
   build silently uses the substituted bytes.
2. The fetch bypasses the build cache, so every layer build re-pulls.
3. `ADD` historically followed redirects without warning; the
   destination is not what the Dockerfile reader sees.

## Severity

`Medium`.

## Languages

Dockerfiles, Containerfiles.

## What rastray flags

```dockerfile
ADD https://example.com/file.tar.gz /tmp/file.tar.gz   # ← flagged
```

## What rastray deliberately does *not* flag

- `ADD ./local/path /dest` (local copy — `ADD`'s legitimate use
  alongside `COPY`).
- `COPY` (in all forms).

## How to fix it

Use `RUN curl` with `--fail` and an explicit checksum:

```dockerfile
RUN curl -fsSL https://example.com/file.tar.gz -o /tmp/file.tar.gz \
    && echo 'deadbeef...  /tmp/file.tar.gz' | sha256sum -c -
```

Even better, build the artefact into a separate image or fetch it
as part of the build context:

```dockerfile
COPY ./vendored/file.tar.gz /tmp/file.tar.gz
```

## References

- [Docker docs: ADD vs COPY](https://docs.docker.com/engine/reference/builder/#add)
- [OWASP Container Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
