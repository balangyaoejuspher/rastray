# RSTR-INJ-005 — Go `exec.Command("sh", "-c", ...)`

## Summary

`exec.Command` is being invoked with a shell wrapper — `sh -c`,
`bash -c`, or `cmd /c` — so the second argument is interpreted as a
shell line. Any attacker-controlled substring becomes shell syntax.
Go's stdlib already protects you against this by accepting an argv
list; the shell wrapper specifically opts back into the dangerous form.

## Severity

`High`.

## Languages

Go.

## What rastray flags

```go
exec.Command("sh", "-c", "ls " + path)            // ← flagged
exec.Command("bash", "-c", fmt.Sprintf("tar czf - %s", path))   // ← flagged
exec.Command("cmd", "/c", "dir " + path)          // ← flagged (Windows)
```

## What rastray deliberately does *not* flag

- `exec.Command("ls", path)` — argv form, no shell.
- `exec.Command("/usr/bin/curl", "-fsSL", url)`.

## How to fix it

Drop the shell wrapper and pass arguments as separate strings — that
*is* the safe form, no escaping required:

```go
cmd := exec.Command("ls", path)
out, err := cmd.Output()
```

```go
cmd := exec.Command("tar", "czf", "-", path)
```

If you genuinely need pipes or redirections, compose them in Go rather
than letting the shell parse the command. `io.Pipe` plus two
`exec.Command`s achieves a pipeline cleanly:

```go
r, w := io.Pipe()
tar := exec.Command("tar", "czf", "-", path)
tar.Stdout = w
gpg := exec.Command("gpg", "--encrypt", "-r", recipient)
gpg.Stdin = r
// run both, close w when tar exits
```

## References

- [`os/exec` package docs](https://pkg.go.dev/os/exec)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
