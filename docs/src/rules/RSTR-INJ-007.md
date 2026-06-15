# RSTR-INJ-007 — PHP command exec on request superglobal

## Summary

A PHP shell-out function (`exec`, `system`, `shell_exec`, `passthru`,
`popen`, `proc_open`, `pcntl_exec`) or the backtick operator runs a
command built from `$_GET`, `$_POST`, `$_REQUEST`, or `$_COOKIE`.
An attacker injects `;` / `&&` / `$(...)` and runs arbitrary OS
commands as the web user.

## Severity

`Critical`.

## Languages

PHP.

## What rastray flags

```php
exec("ping -c 4 " . $_GET['host']);                   // ← flagged
system("ls " . $_POST['dir']);                        // ← flagged
shell_exec("grep " . $_REQUEST['q'] . " /var/log/syslog");  // ← flagged
passthru("zip -r out.zip " . $_GET['target']);        // ← flagged
$out = `ls -la $_GET[d]`;                              // ← flagged (backticks)
```

## What rastray deliberately does *not* flag

- Constant-string commands: `exec('/usr/bin/uptime')`.
- Indirect flow (`$host = $_GET['host']; exec("ping $host")` — same
  one-step taint scope as the rest of rastray).
- Arguments passed via `escapeshellarg(...)` *inside* the call. The
  rule still fires (the regex cannot inspect arguments); suppress
  per-line if you can prove the escape is correct.

## How to fix it

The reliable answer is **don't shell out**. PHP has libraries for
common tasks (`gethostbyname` for DNS, `Imagick` for image work,
etc.). When you must, build the command from a fixed allow-list
and quote variable parts with `escapeshellarg`:

```php
$ALLOWED_HOSTS = ['example.com', 'api.example.com'];

if (!in_array($_GET['host'], $ALLOWED_HOSTS, true)) {
    http_response_code(400);
    exit;
}

$out = shell_exec('ping -c 4 ' . escapeshellarg($_GET['host']));
```

`escapeshellarg` puts the value inside single quotes and escapes any
existing single quotes, so shell metacharacters lose their meaning.
It is **not** a substitute for an allow-list, just defence in depth.

## How to suppress

If the call is genuinely safe after explicit escaping or because the
input source is trusted:

```php
// rastray-ignore: RSTR-INJ-007 — internal cron, $_REQUEST is loopback-only
exec('rsync -a ' . escapeshellarg($_REQUEST['src']) . ' /backup/');
```

## References

- [PHP: escapeshellarg](https://www.php.net/manual/en/function.escapeshellarg.php)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
