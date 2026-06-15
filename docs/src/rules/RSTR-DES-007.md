# RSTR-DES-007 — PHP `unserialize`

## Summary

PHP's `unserialize` deserializes the input into objects and invokes
their magic methods (`__wakeup`, `__destruct`, `__toString`) — even
ones the calling code never names. PHP's huge standard library
provides plenty of useful gadget chains; `unserialize` on
attacker-controlled bytes is a remote-code-execution primitive in
practice, not just in theory.

## Severity

`Critical`.

## Languages

PHP.

## What rastray flags

```php
$data = unserialize($_POST['payload']);            // ← flagged
$data = unserialize(file_get_contents($uploaded)); // ← flagged
```

## What rastray deliberately does *not* flag

- `json_decode(...)` — no object instantiation.
- `unserialize($str, ['allowed_classes' => false])` — strict mode
  available in PHP 7+ that disables object construction.

## How to fix it

Switch to JSON for any external interchange:

```php
$data = json_decode($_POST['payload'], true);
```

If you must keep `unserialize` for an internal channel, enable strict
mode with an explicit class allow-list:

```php
$data = unserialize($blob, [
    'allowed_classes' => ['App\Dto\Job', 'App\Dto\Item'],
]);
```

`'allowed_classes' => false` blocks every class — perfect when you
only intended scalar / array data.

## References

- [PHP `unserialize` docs](https://www.php.net/manual/en/function.unserialize.php)
- [OWASP: PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
