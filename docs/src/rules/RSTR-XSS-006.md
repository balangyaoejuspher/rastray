# RSTR-XSS-006 — PHP `echo` / `print` of request superglobal

## Summary

A PHP page writes `$_GET[...]`, `$_POST[...]`, `$_REQUEST[...]`, or
`$_COOKIE[...]` directly into the HTTP response via `echo`, `print`,
or the short-echo `<?= ?>` form. No HTML escaping in between — the
attacker's input is parsed as HTML in the page's origin, yielding
reflected (and sometimes stored) XSS.

## Severity

`High`.

## Languages

PHP.

## What rastray flags

```php
<?php echo $_GET['name']; ?>                                 <!-- ← flagged -->
<?php print "Hello " . $_POST['name']; ?>                    <!-- ← flagged -->
<p><?= $_REQUEST['msg'] ?></p>                               <!-- ← flagged -->
```

## What rastray deliberately does *not* flag

- Values run through `htmlspecialchars(...)` first:

  ```php
  <?= htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') ?>
  ```

  The regex deliberately requires the superglobal to appear *before*
  any opening `(` on the line, so function-wrapped uses are
  excluded.

- Values rendered through Twig / Blade / Smarty templates with
  auto-escaping on.

## How to fix it

Always escape on output. The canonical helper for HTML context is
`htmlspecialchars` with `ENT_QUOTES` and an explicit charset:

```php
<p>Hello, <?= htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') ?>!</p>
```

For an attribute, the same call works because `ENT_QUOTES` escapes
both single and double quotes:

```php
<a href="<?= htmlspecialchars($_GET['url'], ENT_QUOTES, 'UTF-8') ?>">link</a>
```

For URL contexts (only the path / query of a URL):

```php
<a href="/search?q=<?= rawurlencode($_GET['q']) ?>">search</a>
```

For JavaScript contexts (a value embedded inside an inline `<script>`):

```php
<script>
const user = <?= json_encode($_GET['user'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
</script>
```

If your project uses a template engine (Twig, Blade), prefer those:
auto-escape is on by default and the per-call helper disappears.

## References

- [PHP: htmlspecialchars](https://www.php.net/manual/en/function.htmlspecialchars.php)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
