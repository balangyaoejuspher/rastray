# RSTR-INJ-006 — PHP SQL query built from request superglobal

## Summary

A PHP database call (`mysqli_query`, `pg_query`, `$pdo->query()`, etc.)
concatenates `$_GET[...]`, `$_POST[...]`, `$_REQUEST[...]`, or
`$_COOKIE[...]` directly into the SQL string. Classic SQL injection —
an attacker submits `' OR 1=1 --` and reads or rewrites the entire
table.

## Severity

`Critical`.

## Languages

PHP.

## What rastray flags

Procedural API:

```php
$rows = mysqli_query($db,
    "SELECT * FROM users WHERE id = " . $_GET['id']);    // ← flagged
```

```php
pg_query($conn,
    "DELETE FROM orders WHERE name = '" . $_POST['name'] . "'");  // ← flagged
```

Object-style PDO / mysqli:

```php
$rows = $pdo->query(
    "SELECT * FROM logs WHERE pat = '" . $_REQUEST['pat'] . "'");  // ← flagged
```

## What rastray deliberately does *not* flag

- Calls where the SQL is a constant string with no superglobal
  interpolation.
- Calls where the value flows through an intermediate variable
  (consistent with how every other rastray rule scopes its
  pattern match).
- Prepared-statement use: `$pdo->prepare(...) + ->execute([...])`.

## How to fix it

Use prepared statements with placeholders. With PDO:

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);
$rows = $stmt->fetchAll();
```

With `mysqli`:

```php
$stmt = mysqli_prepare($db, 'SELECT * FROM users WHERE id = ?');
mysqli_stmt_bind_param($stmt, 'i', $_GET['id']);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

For Postgres (`pg_query_params`):

```php
$result = pg_query_params(
    $conn,
    'SELECT * FROM orders WHERE name = $1',
    [$_POST['name']]
);
```

Placeholders are the only safe form. Sanitising with `mysqli_real_escape_string`
helps but is easy to misuse (it does not escape numeric contexts, table
names, or column names); prepared statements remove the foot-gun.

## References

- [PHP: PDO prepared statements](https://www.php.net/manual/en/pdo.prepared-statements.php)
- [PHP: mysqli prepared statements](https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
