# RSTR-SEC-007 — PEM private key in source

## Summary

A `-----BEGIN … PRIVATE KEY-----` block (RSA, EC, Ed25519, or generic
PKCS#8) appears in the repository. Private keys never belong in
source: anyone who clones the repo can sign JWTs, decrypt traffic,
authenticate as the bearer, etc.

## Severity

`Critical`.

## Languages

Any scannable text file.

## What rastray flags

```text
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1J...                       ← flagged
-----END RSA PRIVATE KEY-----
```

```text
-----BEGIN PRIVATE KEY-----                 ← flagged (PKCS#8)
-----BEGIN EC PRIVATE KEY-----              ← flagged
-----BEGIN OPENSSH PRIVATE KEY-----         ← flagged
```

## What rastray deliberately does *not* flag

- Public-key blocks (`PUBLIC KEY`, `CERTIFICATE`).
- Test fixtures that are obviously short / non-keymaterial. Suppress
  with a comment if they're inside a `tests/` directory and the
  fixture is intentionally throwaway.

## How to fix it

1. **Assume the key is compromised.** Issue a new key pair, update
   every system that trusts the old public key, and revoke the old
   one (CRL / OCSP / GitHub SSH key page / Vault rotation).
2. Move the new private key into a secret manager (Vault, AWS Secrets
   Manager, GCP Secret Manager) — *not* an environment variable,
   because envs survive in process listings and crash dumps.
3. Rewrite git history with `git filter-repo --invert-paths --path-glob '*.pem'`.
4. Force-push and document the incident.

A leaked key in a public repo is functionally an active credential
theft until the rotation completes — treat the timeline as P0.

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [GitHub: removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
