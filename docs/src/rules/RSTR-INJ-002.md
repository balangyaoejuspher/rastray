# RSTR-INJ-002 — Python `subprocess(shell=True)` / `os.system`

## Summary

Calling `subprocess.run` (or `.call` / `.Popen`) with `shell=True` —
or using `os.system` — runs the argument through `/bin/sh`. Any
attacker-controlled substring is then interpreted as shell syntax,
so `;`, `&&`, `$(...)`, backticks, redirections, and globbing all
work against you.

## Severity

`High`.

## Languages

Python.

## What rastray flags

```python
import subprocess, os

subprocess.run(f'ls {path}', shell=True)         # ← flagged
subprocess.Popen(cmd, shell=True)                # ← flagged
os.system('curl ' + url)                          # ← flagged
```

## What rastray deliberately does *not* flag

- `subprocess.run(['ls', path])` — argv form, no shell.
- `subprocess.run('ls', shell=False)` — explicit opt-out.

## How to fix it

Pass an argv list and leave `shell=False` (the default):

```python
import subprocess

subprocess.run(['ls', path], check=True)
subprocess.run(['curl', '--fail', url], check=True)
```

If you genuinely need shell features (pipes, here-docs), build the
command from constants and quote any variable parts with `shlex.quote`:

```python
import shlex, subprocess

cmd = f'tar czf - {shlex.quote(path)} | gpg --encrypt -r {shlex.quote(recipient)}'
subprocess.run(cmd, shell=True, check=True)
```

Still — the argv form is almost always better; reach for the shell
only when the pipeline structure cannot be expressed without it.

## References

- [Python `subprocess` security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
