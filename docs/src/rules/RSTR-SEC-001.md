# RSTR-SEC-001 — hard-coded credential pattern

## Summary

A string literal in source code matches a known credential
shape (AWS access key, GitHub PAT, Slack token, etc.) and
also passes an entropy check (≥ 3.0 bits/char Shannon
entropy by default), so it's unlikely to be placeholder
text. Hard-coded credentials in source are one of the most
common high-impact bugs — once the repo leaks the secret
leaks.

## Severity

Varies per token shape (typically `High` to `Critical`).
AWS access keys and GitHub PATs default to `Critical`.

## Languages

All text-classified files (any source code, any config
file).

## What rastray flags

A string literal matching a per-vendor regex pattern (e.g.
`AKIA[0-9A-Z]{16}` for AWS, `ghp_[A-Za-z0-9]{36}` for
GitHub fine-grained PATs) that also passes the entropy
filter.

## What rastray deliberately does *not* flag

- Placeholder strings (`AKIAIOSFODNN7EXAMPLE`,
  `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`) — entropy
  too low.
- Comments / docs / test fixtures that explicitly contain
  example tokens — same reason.

## How to fix it

Rotate the leaked credential **immediately** at the issuing
provider. Then move the credential to:

- An environment variable (`process.env.AWS_ACCESS_KEY_ID`)
- A secret manager (AWS Secrets Manager, Vault, GCP Secret
  Manager, Kubernetes secrets)
- A `.env` file that is `.gitignore`d

The leaked value is now part of git history. Use
[`git-filter-repo`](https://github.com/newren/git-filter-repo)
or [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
to scrub history if you must. Even then, **assume the
secret is compromised** and rotate.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Hard-coded credentials](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [GitGuardian: State of secrets sprawl](https://www.gitguardian.com/state-of-secrets-sprawl-report-2024)
