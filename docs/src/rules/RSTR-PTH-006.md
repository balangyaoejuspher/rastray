# RSTR-PTH-006 — PHP file API on request superglobal

## Summary

`file_get_contents`, `file_put_contents`, `fopen`, `readfile`,
`fpassthru`, or `file` is called with a path derived directly from
`$_GET`, `$_POST`, `$_REQUEST`, or `$_COOKIE`. An attacker submits
`../../etc/passwd` and the application reads or writes outside the
intended directory.

Distinct from [`RSTR-PTH-005`](./RSTR-PTH-005.md): that rule covers
the **include / require** family, which executes PHP. This one covers
generic file reads / writes, which expose or overwrite arbitrary
files but don't execute them.

## Severity

`High`.

## Languages

PHP.

## What rastray flags

```php
$content = file_get_contents($_GET['url']);            // ← flagged
$fp      = fopen($_POST['file'], 'r');                 // ← flagged
readfile($_REQUEST['path']);                           // ← flagged
file_put_contents($_GET['name'], $data);               // ← flagged
```

## What rastray deliberately does *not* flag

- Calls with a constant path: `file_get_contents('/etc/myapp/config.json')`.
- Calls where the value flows through an intermediate variable
  (one-step taint scope, consistent across rastray).

## How to fix it

Strip path components with `basename`, then resolve against a fixed
base directory and verify with `realpath`:

```php
$base = realpath('/var/app/uploads');
$file = realpath($base . '/' . basename($_GET['name']));

if ($file === false || strpos($file, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(404);
    exit;
}

return file_get_contents($file);
```

For URL fetches (where `file_get_contents($_GET['url'])` is actually
*HTTP*-based, not file-based), the bug is server-side request
forgery rather than path traversal. The fix is the same as
[`RSTR-SSRF-001`](./RSTR-SSRF-001.md): allow-list the host and
block private/loopback/metadata IPs before fetching.

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PHP: realpath](https://www.php.net/manual/en/function.realpath.php)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
