# RSTR-IAC-002 — Dockerfile `USER root`

## Summary

A Dockerfile sets `USER root` explicitly (or omits `USER` entirely)
in the final stage, so the container's PID 1 — and every application
process — runs as root. If anything inside the container escapes
(kernel CVE, mounted-host volume, privileged docker socket), the
attacker lands as root on the host.

## Severity

`High`.

## Languages

Dockerfiles, Containerfiles.

## What rastray flags

```dockerfile
FROM alpine:3.20
USER root                                          # ← flagged
CMD ["./server"]
```

## What rastray deliberately does *not* flag

- Final-stage `USER nobody` / `USER 1001` / any non-root user.
- Multi-stage builds where the *builder* stage uses root but the
  final runtime stage drops privileges.

## How to fix it

Create a non-root user and switch to it in the runtime stage:

```dockerfile
FROM alpine:3.20

RUN addgroup -S app && adduser -S app -G app
USER app

WORKDIR /home/app
COPY --chown=app:app . .
CMD ["./server"]
```

If you genuinely need root for an init step (writing to `/etc`,
binding a privileged port), do that in a builder stage or via
capabilities — not by leaving the runtime process as root:

```dockerfile
# install root-only stuff in builder stage
FROM alpine:3.20 AS builder
RUN ...   # root operations

FROM alpine:3.20
USER app
COPY --from=builder /opt/app /opt/app
```

For privileged ports (<1024) in production, terminate at a load
balancer / ingress and bind the app to a high port.

## References

- [Docker docs: USER](https://docs.docker.com/engine/reference/builder/#user)
- [OWASP Container Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
