# DVWA

[`github.com/digininja/DVWA`](https://github.com/digininja/DVWA) — the classic PHP / "Damn Vulnerable Web App."

## Results

| tool            | findings | wall-clock |
|-----------------|---------:|-----------:|
| rastray         |        5 |     0.34 s |
| semgrep         |       45 |    27.9 s  |
| gitleaks        |        5 |     2.1 s  |
| bandit          |   *N/A*  |          — |
| gosec           |   *N/A*  |          — |
| eslint-security |   *N/A*  |          — |

## What rastray fires on

| code           | count | what it catches |
|----------------|------:|------------------|
| `RSTR-INJ-003` |     5 | PHP `eval` |

## Honest observation: DVWA is essentially-indirect

rastray ships PHP-aware rules for SQL injection, command exec,
echo / print of request input, include / require LFI, and file
API LFI:

- [`RSTR-INJ-006`](../rules/RSTR-INJ-006.md) — SQLi via superglobal in the query
- [`RSTR-INJ-007`](../rules/RSTR-INJ-007.md) — command exec on superglobal
- [`RSTR-XSS-006`](../rules/RSTR-XSS-006.md) — echo / print of superglobal
- [`RSTR-PTH-005`](../rules/RSTR-PTH-005.md) — include / require from superglobal
- [`RSTR-PTH-006`](../rules/RSTR-PTH-006.md) — file API on superglobal

None of them fire on DVWA. DVWA's pedagogical style assigns the
superglobal to a local first, then uses the local — a single
indirection that rastray deliberately does not chase (the same
one-step taint scope every other rastray rule uses). For example,
DVWA's SQLi-low source reads:

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

rastray flags neither line in isolation — there's no superglobal in
the `mysqli_query` call, no concatenation in the assignment. The
two-line idiom is below the rule's threshold by design.

The same five PHP rules fire correctly on the **direct** pattern
common in real PHP code:

```php
$rows = mysqli_query($db, "SELECT * FROM u WHERE id = " . $_GET['id']);
exec("ping " . $_POST['host']);
echo $_GET['name'];
include $_REQUEST['page'] . ".php";
$x = file_get_contents($_GET['url']);
```

Semgrep's `p/owasp-top-ten` registry includes PHP rules that span
the assign-then-use boundary, which is why it reports 45 on DVWA.
For codebases that match DVWA's idiom rather than rastray's
direct-sink scope, Semgrep is the better fit; for codebases where
the superglobal appears in the sink, rastray is faster.

## Reproduce

```powershell
powershell -File scripts/benchmarks/run.ps1 -Target dvwa
```
