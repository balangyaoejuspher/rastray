# RSTR-MEM-003 — alloca on attacker-controlled size

## Summary

`alloca(n)` allocates `n` bytes on the **stack** at runtime. Unlike a
heap allocation, an `alloca` failure has no documented return value:
the implementation simply moves the stack pointer down by `n`. If `n`
is larger than the remaining stack space, the new stack pointer
crashes through the page guard into unrelated memory and the program
dies — or, if an attacker controls `n`, becomes a stack-pivot
primitive that lets the attacker re-aim the stack at memory they
already wrote.

The function is non-standard (it's not in C11 or C++) and most
mainstream style guides ban it outright. GCC and Clang offer it via
`<alloca.h>` and the language extension `__builtin_alloca`, but the
standard answer for "I need a temporary buffer whose size is computed
at runtime" is a heap allocation paired with `free`, or in C++ a
`std::vector` / `std::unique_ptr<T[]>`.

## Severity

`High`.

## Languages

C, C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`, `.hh`, `.hxx`).

## What rastray flags

```c
#include <alloca.h>

char *tmp = alloca(size);                       // ← flagged
char *buf = alloca(n * sizeof(int));            // ← flagged
```

## What rastray deliberately does *not* flag

- `malloc` / `calloc` / `realloc`. They have a return value to check,
  and a failure is recoverable.
- VLAs (`char buf[size]`). Different problem class — already
  deprecated in C++ and optional in C11+.
- `__builtin_alloca` if you've namespaced around the regex.

## How to fix it

Use the heap. In C:

```c
char *tmp = malloc(size);
if (tmp == NULL) {
    return -1;                                  // recoverable failure
}
// …
free(tmp);
```

In C++, use an RAII wrapper that handles cleanup automatically:

```cpp
auto tmp = std::make_unique<char[]>(size);
// no manual free
```

Or a `std::vector<char>` if you'll resize it:

```cpp
std::vector<char> tmp(size);
```

If you genuinely need a stack buffer for performance reasons and the
size is small and bounded, declare a fixed-size array with a
`static_assert`:

```c
char tmp[256];
assert(size <= sizeof(tmp));
```

## How to suppress

If `alloca` is intentional and the size is provably bounded by a
small compile-time constant, suppress per-line:

```c
// rastray-ignore: RSTR-MEM-003 — fixed-bounded by MAX_PATH (260)
char *tmp = alloca(MAX_PATH);
```

But seriously, just use a fixed-size array.

## References

- [Linux man-pages: alloca(3)](https://man7.org/linux/man-pages/man3/alloca.3.html)
- [Google C++ Style Guide — Avoid alloca](https://google.github.io/styleguide/cppguide.html#Forbidden_features)
- [CWE-770](https://cwe.mitre.org/data/definitions/770.html)
