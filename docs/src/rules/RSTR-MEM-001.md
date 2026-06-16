# RSTR-MEM-001 — strcpy / strcat / gets / sprintf

## Summary

The C standard library ships several string-copying functions that
take a destination buffer and copy into it without checking the
destination's size. If the source data is longer than the destination
allocation, the write spills into adjacent memory — classic buffer
overflow. Modern C and C++ replace each of these with a length-bounded
or self-allocating alternative; the unbounded forms have been the
direct cause of dozens of CVE-tagged vulnerabilities since 1990.

`gets` is the most extreme case (no destination size argument at all)
and was actually removed from the C11 standard. `sprintf` and
`vsprintf` are next: they take a destination but no size, so a
malicious format substitution writes past the end. `strcpy` and
`strcat` round out the family.

## Severity

`Critical`.

## Languages

C, C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`, `.hh`, `.hxx`).

## What rastray flags

```c
char buf[64];

strcpy(buf, src);                     // ← flagged
strcat(buf, more);                    // ← flagged
gets(buf);                            // ← flagged (and removed in C11)
sprintf(buf, "%s\n", src);            // ← flagged

va_list ap;
vsprintf(buf, fmt, ap);               // ← flagged
```

## What rastray deliberately does *not* flag

- The bounded variants: `strncpy`, `strncat`, `snprintf`, `vsnprintf`.
- `fgets` (line input with a size argument).
- `strlcpy` / `strlcat` (the BSD safer-copy family).
- `std::string` operations in C++.

## How to fix it

Each banned function has a 1:1 bounded replacement:

| banned | replacement | notes |
|--------|-------------|-------|
| `strcpy(d, s)` | `snprintf(d, sizeof(d), "%s", s)` or `strlcpy(d, s, sizeof(d))` | both null-terminate |
| `strcat(d, s)` | `strncat(d, s, sizeof(d) - strlen(d) - 1)` or `strlcat(d, s, sizeof(d))` | the `-1` reserves room for the null byte |
| `gets(buf)` | `fgets(buf, sizeof(buf), stdin)` | also strip the trailing newline if present |
| `sprintf(d, fmt, …)` | `snprintf(d, sizeof(d), fmt, …)` | check the return value for truncation |
| `vsprintf(d, fmt, ap)` | `vsnprintf(d, sizeof(d), fmt, ap)` | same return-value check |

In C++, prefer `std::string` and `std::format` (C++23) or `fmt::format`
which manage their own bounds:

```cpp
#include <string>
#include <format>

std::string buf = std::format("{}\n", src);
```

## How to suppress

If a call is genuinely safe — for example, `sprintf(buf, "%d", n)`
where the destination is provably large enough for any `int` —
suppress per-line:

```c
// rastray-ignore: RSTR-MEM-001 — buf is char[12], int max is 11 chars + sign
sprintf(buf, "%d", n);
```

Even then, `snprintf` gains nothing in cost and removes the proof
obligation.

## References

- [SEI CERT C STR07-C](https://wiki.sei.cmu.edu/confluence/display/c/STR07-C.+Use+the+bounds-checking+interfaces+for+string+manipulation)
- [Microsoft: Banned APIs](https://learn.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10))
- [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-242 — Use of Inherently Dangerous Function](https://cwe.mitre.org/data/definitions/242.html)
