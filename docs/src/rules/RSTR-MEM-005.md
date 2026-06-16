# RSTR-MEM-005 — raw `new` outside a smart pointer

## Summary

A raw `new TypeName(args)` allocation appears in C++ source. The
returned pointer is a bare `T *` — the language doesn't track who
owns it, who must `delete` it, or what happens if an exception
unwinds the stack between this allocation and the eventual `delete`.
Modern C++ (C++11+) provides `std::unique_ptr<T>` and
`std::shared_ptr<T>` for exactly this case: the smart pointer's
destructor frees the memory, exception-safety is automatic, and
ownership is visible at every call site.

This is rastray's first **`Confidence::Low`** rule: many codebases
have audited raw-`new` patterns (custom allocators, intrusive
reference counting, etc.) where the pattern is intentional. The
finding is heuristic — it can't tell from the call site alone whether
the result is wrapped in a smart pointer one line later. It surfaces
by default; tighten with `--min-confidence high` to filter it out
project-wide once you've audited.

## Severity

`Medium`. The damage is real (memory leak on the exception path) but
not directly exploitable — the runtime impact is degraded
performance over time, not arbitrary code execution.

## Confidence

`Low`. By design — see the rationale above. The intent is to surface
the pattern for review, not to block CI.

## Languages

C, C++ (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`, `.hh`, `.hxx`).

## What rastray flags

```cpp
auto *p = new Widget(args);                 // ← flagged
return new Foo{};                           // ← flagged
auto *s = new std::string("abc");           // ← flagged
char *buf = new char[size];                 // ← flagged
```

## What rastray deliberately does *not* flag

- Smart-pointer factory functions: `std::make_unique<T>(args)`,
  `std::make_shared<T>(args)`. These don't contain the literal
  `new ` keyword.
- Placement new (`new (buf) T(args)`) — different mechanism, doesn't
  allocate, can't leak.
- Operator-new overloads or custom allocators referenced via
  `T::operator new`.

## How to fix it

Use `std::make_unique` or `std::make_shared`:

```cpp
#include <memory>

auto p = std::make_unique<Widget>(args);    // unique ownership
auto p = std::make_shared<Foo>();           // shared ownership

// for arrays
auto buf = std::make_unique<char[]>(size);
```

Both forms release the allocation when the smart pointer goes out of
scope, even if an exception unwinds the stack between allocation and
the next statement. Ownership is visible: the type is
`std::unique_ptr<Widget>`, not a bare `Widget *`.

For very performance-sensitive cases where you've measured the
overhead, consider an arena allocator or `std::pmr::polymorphic_allocator`
rather than raw `new`.

## How to suppress

Per-line for an audited site:

```cpp
// rastray-ignore: RSTR-MEM-005 — placement allocator owns the lifetime
T *p = pool.allocate<T>(args);
```

Project-wide if your team has agreed on raw-`new` patterns:

```sh
rastray --min-confidence high
```

Or in `.rastray.toml`:

```toml
[rules]
"RSTR-MEM-005" = false
```

## References

- [C++ Core Guidelines R.11 — Avoid `new` and `delete`](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Rr-newdelete)
- [`std::make_unique`](https://en.cppreference.com/w/cpp/memory/unique_ptr/make_unique)
- [CWE-401 — Memory Leak](https://cwe.mitre.org/data/definitions/401.html)
