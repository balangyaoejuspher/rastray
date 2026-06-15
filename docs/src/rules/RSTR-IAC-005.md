# RSTR-IAC-005 — `chmod 777`

## Summary

A Dockerfile sets file or directory permissions to `777`
(world-readable + world-writable + world-executable). Inside a
container that's running as root anyway this is mostly cosmetic
("everything was already root-owned"), but the moment the runtime
drops to a non-root user or a different container mounts the same
volume, the `777` becomes an actual privilege grant to whichever
process can reach the path.

It is essentially always wrong — the cases where `0755` (directories)
or `0644` (files) is insufficient are rare enough that the rule
fires for review.

## Severity

`High`. Cheap to fix, common cause of real escalations when the
container model later changes.

## Languages

Dockerfiles, Containerfiles.

## What rastray flags

```dockerfile
RUN chmod 777 /var/app                            # ← flagged
RUN chmod -R 0777 /etc/secrets                    # ← flagged
```

## What rastray deliberately does *not* flag

- `chmod 644`, `chmod 755`, `chmod +x`, etc.
- `chmod` on a path the rule cannot resolve to a real file.

## How to fix it

Compute the actual minimum permissions:

- Files: `0644` (or `0640` if a group should read).
- Executables: `0755`.
- Directories: `0755` (or `0750`).
- Sensitive files (keys, env-files): `0600`.

```dockerfile
RUN chmod 0755 /var/app && chown app:app /var/app
```

If the issue is "writable by my non-root user", set ownership instead
of broadening permissions:

```dockerfile
RUN chown -R app:app /var/app
```

## References

- [OWASP Container Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
