# RSTR-INJ-004 — Node `child_process.exec` with template literal

## Summary

`child_process.exec` (and `execSync`) runs its command through `/bin/sh`.
When the command is built with template-literal interpolation or string
concatenation, any attacker-controlled substring is interpreted as
shell syntax — the standard command-injection vulnerability.

## Severity

`High`.

## Languages

JavaScript, TypeScript.

## What rastray flags

```js
const { exec } = require('child_process');

exec(`ls ${path}`);                                 // ← flagged
exec('curl ' + url);                                // ← flagged
execSync(`tar czf - ${dir}`);                       // ← flagged
```

## What rastray deliberately does *not* flag

- `execFile(file, [args])` — no shell.
- `spawn(cmd, [args])` — no shell.
- `exec('ls')` with a constant string.

## How to fix it

Use `execFile` or `spawn` with an argv array:

```js
const { execFile, spawn } = require('child_process');

execFile('ls', [path], (err, stdout) => { ... });

spawn('tar', ['czf', '-', dir]);
```

If you need shell features (pipes, redirections), build the command
from constants and quote each variable with a safe quoter:

```js
import { quote } from 'shell-quote';

const cmd = `tar czf - ${quote([path])} | gpg --encrypt -r ${quote([recipient])}`;
exec(cmd);
```

`shell-quote` (or `shlex` on the Python side) does what
`shellescape` does in safer shells.

## References

- [Node `child_process` docs — security](https://nodejs.org/api/child_process.html#child_process_child_process_exec_command_options_callback)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
