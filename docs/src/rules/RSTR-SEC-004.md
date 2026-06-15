# RSTR-SEC-004 — Slack bot token (`xoxb-…`)

## Summary

A Slack bot token (`xoxb-` + numeric IDs + secret material) is
embedded in the repository. The token authenticates as the bot
identity and can post to channels, read DMs the bot is in, and call
any Slack Web API endpoint that the bot's OAuth scopes permit.

## Severity

`High`.

## Languages

Any scannable text file.

## What rastray flags

```python
SLACK_BOT_TOKEN = "xoxb-EXAMPLE-EXAMPLE-EXAMPLEEXAMPLEEXAMPLEEXAMPLE"
```

## What rastray deliberately does *not* flag

- Slack *user* tokens (`xoxp-…`) — separate rule eventually; current
  set covers bot tokens because those are the common-in-source case.
- Documentation placeholders.

## How to fix it

1. **Revoke** at <https://api.slack.com/apps> → your app → OAuth &
   Permissions → "Revoke token".
2. Generate a new install / token.
3. Store in environment or secret manager:

   ```python
   import os
   slack = WebClient(token=os.environ['SLACK_BOT_TOKEN'])
   ```
4. Rewrite git history if the token was ever committed; Slack's
   bot-token leak detection often catches this within minutes and
   auto-revokes, but don't rely on that.

## References

- [Slack: securing your tokens](https://api.slack.com/authentication/best-practices)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
