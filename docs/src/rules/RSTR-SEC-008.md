# RSTR-SEC-008 — npm access token (`npm_…`)

## Summary

An npm access token (`npm_` + 36 base62 chars) appears in the
repository. Whoever has the token can publish new versions of any
package the token owner publishes — a textbook supply-chain compromise
vector.

## Severity

`High`.

## Languages

Any scannable text file (commonly `.npmrc`, CI config, shell scripts).

## What rastray flags

```ini
//registry.npmjs.org/:_authToken=npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE12
```

## What rastray deliberately does *not* flag

- Documentation placeholders.
- Tokens in environment-variable form: `NPM_TOKEN=${NPM_TOKEN}`.

## How to fix it

1. **Revoke** at <https://www.npmjs.com/settings/&lt;user&gt;/tokens>.
2. Create a new token. For CI, use a **granular access token** scoped
   to the specific package(s) you publish.
3. Move to CI secret store (GitHub Actions `secrets.NPM_TOKEN`) and
   reference from `.npmrc`:

   ```ini
   //registry.npmjs.org/:_authToken=${NPM_TOKEN}
   ```
4. Rewrite git history if the token ever landed in a commit.
5. Audit the npm package's published versions; if anything looks
   out-of-band, unpublish and warn downstream consumers.

## References

- [npm: about access tokens](https://docs.npmjs.com/about-access-tokens)
- [npm: granular access tokens](https://docs.npmjs.com/creating-and-viewing-access-tokens#granular-access-tokens)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
