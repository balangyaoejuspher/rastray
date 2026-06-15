# RSTR-SEC-003 — GitHub fine-grained PAT (`github_pat_…`)

## Summary

A GitHub fine-grained personal access token (`github_pat_` + base62
material) appears in the repository. Fine-grained tokens are
scope-restricted but still grant API access to whatever repositories
and permissions the token was minted with — usually enough to read
private code or push to selected repos.

## Severity

`High`.

## Languages

Any scannable text file.

## What rastray flags

```yaml
GH_PAT: github_pat_EXAMPLEAAAAAAAAAAA_EXAMPLEAAAAAAAAAAAAAAAAAAAAAA
```

## What rastray deliberately does *not* flag

- Documentation placeholders with low entropy.

## How to fix it

Same playbook as classic PATs ([`RSTR-SEC-002`](./RSTR-SEC-002.md)):

1. Revoke at <https://github.com/settings/tokens>.
2. Mint a replacement with the narrowest permissions and shortest
   expiry the use case allows.
3. Move to environment / secret manager.
4. Rewrite the offending history.

The fine-grained format is the recommended replacement for classic
PATs — keep using fine-grained ones, just keep them out of source.

## References

- [GitHub: fine-grained personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#about-personal-access-tokens)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
