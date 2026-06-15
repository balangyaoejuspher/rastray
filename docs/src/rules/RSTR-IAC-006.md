# RSTR-IAC-006 — `curl | sh` pattern

## Summary

A Dockerfile (or build script generally) pipes the output of `curl`
straight into a shell: `curl https://example.com/install.sh | sh`.
There is no integrity check on the bytes that the shell ends up
executing. If the upstream is compromised, an attacker on the
network can MITM, DNS gets poisoned, or TLS fails open for any other
reason, the build silently runs whatever bytes arrived.

The pattern is convenient enough that vendors keep recommending it
("for the quickest install, run …"). Convenience does not change the
threat model.

## Severity

`High`.

## Languages

Dockerfiles, Containerfiles.

## What rastray flags

```dockerfile
RUN curl -fsSL https://get.example.com | sh                   # ← flagged
RUN wget -qO- https://example.com/install.sh | bash           # ← flagged
RUN curl https://example.com/setup.py | python                # ← flagged
```

## What rastray deliberately does *not* flag

- Downloads written to a file *and* checksum-verified before
  execution.
- Installs via the distro package manager (`apt-get`, `apk`, `dnf`)
  — those run their own signature verification.

## How to fix it

Download, verify, then execute:

```dockerfile
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \
    && echo 'deadbeef...  /tmp/install.sh' | sha256sum -c - \
    && sh /tmp/install.sh \
    && rm /tmp/install.sh
```

For tools you install regularly, vendor the installer into your
repository and commit the checksum next to it — the chain of
custody runs from your reviewers to the binary in one step.

If the vendor signs releases with GPG, prefer that:

```dockerfile
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \
    && curl -fsSL https://example.com/install.sh.asc -o /tmp/install.sh.asc \
    && gpg --verify /tmp/install.sh.asc /tmp/install.sh \
    && sh /tmp/install.sh
```

## References

- [Dan Walsh: pipe curl to bash is bad](https://www.redhat.com/sysadmin/curl-bash-security)
- [CWE-494](https://cwe.mitre.org/data/definitions/494.html)
- [CWE-829](https://cwe.mitre.org/data/definitions/829.html)
