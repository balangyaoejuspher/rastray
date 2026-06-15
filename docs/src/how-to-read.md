# How to read these pages

Every rule page on this site follows the same template:

## Summary

A one-paragraph description of the bug class and why it
matters. If you only have ten seconds, this is the part to
read.

## Severity

One of ``Critical`` / ``High`` / ``Medium`` / ``Low`` /
``Info``. Severities map to your shell's exit code via the
``--fail-on`` flag.

## Languages

Which file extensions the rule scans. A Python-only rule
will never look at a `.go` file.

## What rastray flags

The exact pattern shape that triggers a finding. Includes:

- the regex (or AST-query) the analyzer uses, in plain
  English;
- a minimal **true-positive example** — the smallest piece
  of code that fires the rule.

## What rastray deliberately does *not* flag

The shapes that look similar but are safe. Most rastray
rules ship with at least one explicit "discriminator test"
that proves the safe form is not flagged. We list those
here so you can copy-paste the safe form straight into your
code.

## Why the finding message looks the way it does

Most rastray security rules use the
**captured-call-site message** convention: the exact code
fragment that matched is interpolated into the finding
message. That way, if the rule fires 50 times in one repo,
each finding has a distinguishable message instead of 50
copies of the same generic warning.

## How to fix it

The canonical remediation — usually a copy-paste-able code
snippet showing the hardened form.

## How to suppress this finding

Three options, in order of preference:

1. **Fix the code.** Almost always the right answer.
2. **Inline suppression**: add ``// rastray-ignore: RSTR-XXX-NNN``
   (or ``# rastray-ignore: ...`` in Python, etc.) on the
   line above the finding. Use ``rastray-ignore-line:`` to
   suppress only that line, or ``rastray-ignore-file:`` to
   suppress the whole file.
3. **Project-level suppression** in ``.rastray.toml``:
   ```toml
   [rules]
   "RSTR-XXX-NNN" = false
   ```
   or downgrade severity:
   ```toml
   [rules]
   "RSTR-XXX-NNN" = { severity = "low" }
   ```

## References

CWE entries, OWASP cheat sheets, language-specific docs,
and any blog posts that describe the bug class with the
clearest examples.
