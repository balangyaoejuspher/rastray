# RSTR-IAC-001 — Dockerfile `FROM <image>:latest` (or untagged)

## Summary

A Dockerfile `FROM` line references an image with the `:latest` tag
or no tag at all (which defaults to `:latest`). Builds become
non-reproducible — the same `docker build` produces a different
image tomorrow than today — and a malicious or compromised upstream
tag silently rolls into your build pipeline.

## Severity

`Medium`. Reproducibility is the immediate concern; supply-chain
substitution is the worst case.

## Languages

Dockerfiles, Containerfiles, `Dockerfile.*` variants.

## What rastray flags

```dockerfile
FROM alpine:latest                                # ← flagged
FROM node                                          # ← flagged (defaults to :latest)
FROM ghcr.io/example/api:latest                    # ← flagged
```

## What rastray deliberately does *not* flag

- A specific semver tag: `FROM alpine:3.20`.
- A digest pin: `FROM alpine@sha256:...`.
- `scratch` (no tag possible).

## How to fix it

Pin to a specific tag for human readability, or to a digest for
strict reproducibility:

```dockerfile
FROM alpine:3.20            # tag pin — gets minor/patch updates
FROM alpine@sha256:beefbeef...   # digest pin — byte-exact every build
```

For multi-stage builds, the digest-pinning effort pays off where it
matters most: the **final runtime stage**. Build stages can take the
tag pin.

Renovate / Dependabot both understand the digest-pin convention and
will keep the SHA up to date.

## References

- [Docker docs: Best practices — pin image versions](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#pin-base-image-versions)
- [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html)
