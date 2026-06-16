# RSTR-INJ-012 — Java Runtime.exec / ProcessBuilder with concat

## Summary

A Java program calls `Runtime.getRuntime().exec(...)` or constructs a
`new ProcessBuilder(...)` from a single concatenated string —
`"command " + variable`. The single-string form goes through the
shell, so any shell metacharacter (`;`, `|`, `&`, backtick, `$()`)
inside the variable becomes a separator and runs whatever follows
with the program's privileges.

The fix is mechanical: instead of building a single shell command,
pass each argument as a separate slot in a `String[]` array (or as
varargs to `ProcessBuilder`). The OS receives `argv[0]` as the
program and `argv[1..]` as opaque strings; no shell ever parses
them.

## Severity

`Critical`.

## Languages

Java, Kotlin (`.java`, `.kt`, `.kts`).

## What rastray flags

```java
String host = request.getParameter("host");
Runtime.getRuntime().exec("ping " + host);                          // ← flagged
new ProcessBuilder("git log " + branch);                            // ← flagged
```

## What rastray deliberately does *not* flag

Argv-array and varargs forms — the recommended remediation:

```java
Runtime.getRuntime().exec(new String[] {"ping", "-c", "4", host});
new ProcessBuilder("git", "log", branch);
```

Constant-string commands:

```java
Runtime.getRuntime().exec("uptime");
```

## How to fix it

Replace the single concatenated string with an argv array. The first
slot is the executable, every other slot is one argument:

```java
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
Process proc = pb.start();
```

Even if `host` contains `;rm -rf /`, the kernel passes that whole
string as one argument to `ping`; `ping` rejects it as a malformed
hostname; nothing executes.

If you genuinely need a shell (e.g. globbing), allow-list the input
first:

```java
private static final Pattern SAFE_BRANCH = Pattern.compile("[a-zA-Z0-9_/.-]+");
if (!SAFE_BRANCH.matcher(branch).matches()) {
    throw new IllegalArgumentException("invalid branch name");
}
```

## How to suppress

If a call is provably safe (constant + sanitized input that's been
audited), suppress per-line:

```java
// rastray-ignore: RSTR-INJ-012 — branch is a tag name validated by SAFE_BRANCH above
Runtime.getRuntime().exec("git fetch " + branch);
```

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [SEI CERT Java IDS07-J](https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec()+method)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-88 — Argument Injection](https://cwe.mitre.org/data/definitions/88.html)
