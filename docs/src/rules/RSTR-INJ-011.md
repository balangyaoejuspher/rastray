# RSTR-INJ-011 — C system / popen / exec* with non-literal argument

## Summary

A call to `system`, `popen`, `execlp`, `execvp`, or `execve` in C/C++
takes a non-literal first argument — that is, the command string is
built from a variable rather than written inline as a quoted string.
If any part of the variable came from user input, environment, or a
network read, the call hands the OS shell an attacker-controlled
command line. The shell parses metacharacters (`;`, `|`, `&`,
backticks, `$()`) and runs whatever follows, with the privileges of
the current process.

Note that `system` and `popen` always invoke `/bin/sh` even if the
command itself is a fully-qualified path, so the attacker doesn't
even need to find a writable directory in `PATH` — the shell is
right there.

## Severity

`Critical`.

## Languages

C, C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`, `.hh`, `.hxx`).

## What rastray flags

```c
char buf[256];
fgets(buf, sizeof(buf), stdin);

system(buf);                                    // ← flagged
popen(query, "r");                              // ← flagged
execlp(prog, prog, NULL);                       // ← flagged
```

## What rastray deliberately does *not* flag

- String-literal arguments: `system("/bin/uptime")`,
  `popen("/usr/bin/sort -u /tmp/in", "r")`. These are fixed at
  compile time.
- Raw string literals (`R"(...)"` in C++).
- `execve` / `execvp` with a fixed `argv` array — the argv pattern
  doesn't go through a shell and is the recommended remediation.

## How to fix it

The reliable answer is **don't shell out**. C has direct calls for
most things you'd otherwise spawn (`opendir`/`readdir` for `ls`,
`stat` for `test`, `unlink` for `rm`).

When you do need to launch a process, use `execve` / `execvp` with a
fixed `argv` array — no shell, no metacharacter parsing:

```c
char *argv[] = {"/usr/bin/ping", "-c", "4", host, NULL};
pid_t pid = fork();
if (pid == 0) {
    execvp(argv[0], argv);
    _exit(127);
}
waitpid(pid, &status, 0);
```

`host` here is *one argv slot*, so even if it contains `;` or backticks
the kernel passes it as a single argument to `ping` and `ping` rejects
it as a malformed hostname. No shell ever sees it.

If you must use `system` for a fixed command, make sure the entire
argument is a string literal:

```c
system("/usr/bin/uptime");                      // OK — literal, no input
```

## How to suppress

If the input is provably trusted (e.g. comes from a config file the
running user owns) and you've already validated it against an
allow-list, suppress per-line:

```c
// rastray-ignore: RSTR-INJ-011 — cmd is from /etc/myapp.conf, root-owned
system(cmd);
```

## References

- [SEI CERT C ENV33-C](https://wiki.sei.cmu.edu/confluence/display/c/ENV33-C.+Do+not+call+system())
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-88 — Argument Injection](https://cwe.mitre.org/data/definitions/88.html)
