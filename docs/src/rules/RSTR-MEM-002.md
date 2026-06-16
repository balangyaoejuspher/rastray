# RSTR-MEM-002 — scanf with unbounded %s

## Summary

A `scanf`-family call uses `%s` (or `%[…]`) without a width specifier.
The format directive reads characters into the destination buffer
until it encounters whitespace — and if the input is longer than the
buffer, the write overflows. The buffer's declared size is *not*
visible to `scanf` at runtime, so the only protection is the width
specifier in the format string itself.

This is one of the most common buffer-overflow vectors in C teaching
material and legacy code: the call looks innocuous next to a
"reasonable" buffer like `char name[64]`, and most inputs fit, so
the bug goes undetected until someone hands the program a long line.

## Severity

`High`.

## Languages

C, C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`, `.hh`, `.hxx`).

## What rastray flags

```c
char name[64];

scanf("%s", name);                          // ← flagged
sscanf(input, "%d %s", &age, name);         // ← flagged

FILE *fp = fopen(path, "r");
fscanf(fp, "%s", line);                     // ← flagged
```

The vararg variants are also flagged: `vscanf`, `vfscanf`, `vsscanf`.

## What rastray deliberately does *not* flag

- Width-specified `%s`: `scanf("%63s", name)`.
- Other format directives: `%d`, `%f`, `%c`, `%lf`.
- `fgets(buf, sizeof(buf), stdin)` — bounded by construction.
- `getline` — self-allocating, can't overflow.

## How to fix it

The width is one less than the destination size (leaves room for the
null terminator):

```c
char name[64];
scanf("%63s", name);                        // explicit width
```

For the common "read a line" case, `fgets` is simpler and safer:

```c
char line[256];
if (fgets(line, sizeof(line), stdin) != NULL) {
    line[strcspn(line, "\n")] = '\0';       // strip trailing newline
}
```

For unbounded line input, `getline` allocates as much as it needs:

```c
char *line = NULL;
size_t cap = 0;
if (getline(&line, &cap, stdin) > 0) {
    // …
}
free(line);
```

In C++, `std::getline` over a `std::string` is the idiomatic choice.

## How to suppress

If the format width is computed dynamically and the regex can't see it
(rare):

```c
// rastray-ignore: RSTR-MEM-002 — width is pinned via WIDTH macro = sizeof(name)-1
char fmt[16];
snprintf(fmt, sizeof(fmt), "%%%zus", sizeof(name) - 1);
scanf(fmt, name);
```

## References

- [SEI CERT C INT05-C](https://wiki.sei.cmu.edu/confluence/display/c/INT05-C.+Do+not+use+input+functions+to+convert+character+data+if+they+cannot+handle+all+possible+inputs)
- [SEI CERT C ARR38-C](https://wiki.sei.cmu.edu/confluence/display/c/ARR38-C.+Guarantee+that+library+functions+do+not+form+invalid+pointers)
- [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
