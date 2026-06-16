# RSTR-MEM-004 — memcpy / memmove with strlen length

## Summary

A `memcpy` or `memmove` call uses `strlen(src)` as its length argument.
This is almost always an off-by-one bug: `strlen` returns the number
of characters before the null terminator, *not including* the null
byte itself. After the copy, the destination buffer's last position
holds the source's last non-null character — and whatever was there
before the copy still occupies the byte that should be the
terminator. Subsequent string operations on the destination read past
the intended end of the data and produce undefined behaviour, leak
memory contents, or hand attackers a buffer-overflow primitive.

This idiom is most common in code translated from C++ (where
`std::string::size()` does *not* include the terminator and the
language handles the difference) or from languages with bounded
string types (Go, Rust, Pascal). In raw C, the rule is: `strlen + 1`,
or use `strcpy`, or use `snprintf`.

## Severity

`Medium`.

## Languages

C, C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`, `.hh`, `.hxx`).

## What rastray flags

```c
char dst[256];
memcpy(dst, src, strlen(src));                  // ← flagged
memmove(out, in, strlen(in));                   // ← flagged
```

## What rastray deliberately does *not* flag

- `memcpy(dst, src, strlen(src) + 1)` — correctly includes the null.
- `memcpy(dst, src, sizeof(buf))` — fixed-size copy.
- `memcpy(dst, src, n)` — explicit length variable.

## How to fix it

Three idiomatic options:

**(1) Add `+ 1` if you genuinely want a null-terminated copy:**

```c
memcpy(dst, src, strlen(src) + 1);
```

**(2) Use `strcpy` (or its bounded variant) which terminates for you:**

```c
strncpy(dst, src, sizeof(dst) - 1);
dst[sizeof(dst) - 1] = '\0';
```

Or the BSD `strlcpy`:

```c
strlcpy(dst, src, sizeof(dst));
```

**(3) Use `snprintf` (forms a null-terminated copy by construction):**

```c
snprintf(dst, sizeof(dst), "%s", src);
```

In C++, prefer `std::string` assignment which handles all of this
internally:

```cpp
std::string dst = src;                          // src is std::string or const char *
```

## How to suppress

If you genuinely want to copy *only* the bytes (not the terminator) —
for example, splicing a substring into a manually-managed wire
format — suppress per-line:

```c
// rastray-ignore: RSTR-MEM-004 — wire format puts terminator at end of frame
memcpy(frame_payload, src, strlen(src));
frame[frame_len + strlen(src)] = '\0';
```

## References

- [SEI CERT C STR03-C](https://wiki.sei.cmu.edu/confluence/display/c/STR03-C.+Do+not+inadvertently+truncate+a+string)
- [CWE-170 — Improper Null Termination](https://cwe.mitre.org/data/definitions/170.html)
- [CWE-193 — Off-by-one Error](https://cwe.mitre.org/data/definitions/193.html)
