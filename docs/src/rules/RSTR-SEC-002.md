# RSTR-SEC-002 — GitHub personal access token (`ghp_…`)

## Summary

A string matching GitHub's classic personal access token format
(`ghp_` + 36 base62 chars) appears in the repository. Anyone with the
token can act as the user on the GitHub API, including pushing to
private repos, creating releases, and reading workflow secrets.

## Severity

`High`.

## Languages

Any scannable text file — source, config, manifests.

## What rastray flags

```python
GH_TOKEN = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1234"   # ← flagged
```

The matcher requires the literal `ghp_` prefix plus a high-entropy
suffix to avoid flagging documentation snippets that obviously use
filler text (`ghp_XXXX...`).

## What rastray deliberately does *not* flag

- Tokens read from environment variables: `os.environ['GH_TOKEN']`.
- Documentation that shows the *format* with placeholder text
  (`ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`) — low entropy.

## How to fix it

1. **Revoke immediately** at
   <https://github.com/settings/tokens>. The token is now public
   regardless of whether you push the fix; assume hostile use.
2. Generate a fresh token with the smallest scope that does the job.
3. Move the secret to an environment variable or a secret manager,
   and load it at runtime:

   ```python
   import os
   GH_TOKEN = os.environ['GH_TOKEN']
   ```
4. **Rewrite history** if the token ever appeared in a commit:

   ```sh
   git filter-repo --replace-text expressions.txt
   git push --force-with-lease
   ```

   *Force-pushing the rewrite alone does not erase the secret* —
   GitHub caches commit blobs for 90 days; the revocation in step 1 is
   what actually contains the damage.

## References

- [GitHub: about authentication with a PAT](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [GitHub: removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
