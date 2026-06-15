# RSTR-SEC-005 — Stripe live secret key (`sk_live_…`)

## Summary

A Stripe **live mode** secret key (`sk_live_` + 24 base62 chars) is
embedded in the repository. Anyone with this key can charge cards,
issue refunds, read customer payment data, and perform every
write-level action against the Stripe account.

## Severity

`Critical`.

## Languages

Any scannable text file.

## What rastray flags

```python
STRIPE_KEY = "sk_live_<REDACTED-24-CHAR-SECRET>"   # ← flagged
```

The matcher requires the `sk_live_` prefix specifically — test-mode
keys (`sk_test_…`) are not flagged because they cannot move real
money.

## What rastray deliberately does *not* flag

- `sk_test_…` test-mode keys (different rule could fire on those if
  you ever add one — current set is live-only).
- `pk_live_…` publishable keys (intended to be shipped to the browser).

## How to fix it

1. **Roll the key immediately** in the Stripe Dashboard
   (Developers → API keys → Roll). The old key stops working in 12
   hours by default; for a confirmed leak, set the rollover to
   "Immediately."
2. Audit the Events log for the past 24-72 hours and look for
   unfamiliar API requests (`request.api_method`, request IP).
3. Move the new key out of source into environment / Vault / AWS
   Secrets Manager.
4. Rewrite the git history that contains the leaked key.
5. If the key has been in source for any length of time and the repo
   was ever public, treat the account as fully compromised and
   contact Stripe support.

## References

- [Stripe: rolling API keys](https://docs.stripe.com/keys#rolling)
- [Stripe: detecting compromised keys](https://docs.stripe.com/security)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
