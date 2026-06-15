# RSTR-PTH-003 — Java `new File(servletRequest.getParameter(...))`

## Summary

A Java servlet builds a `File` (or `Paths.get`) using request
parameters directly. The classic input `../../etc/passwd` (or
`..\..\windows\win.ini` on Windows) lets an attacker escape any
intended directory.

## Severity

`High`.

## Languages

Java, Kotlin.

## What rastray flags

```java
File f = new File(request.getParameter("name"));               // ← flagged
File f = new File("uploads/" + request.getParameter("name"));  // ← flagged
```

```java
Path p = Paths.get(request.getParameter("name"));              // ← flagged
```

## What rastray deliberately does *not* flag

- `Paths.get(SAFE_DIR, FilenameUtils.getName(input))`.
- Reads of constant paths.

## How to fix it

Canonicalize the resolved path and verify it stays inside the
intended base. With Apache Commons `FilenameUtils`:

```java
import java.io.File;
import org.apache.commons.io.FilenameUtils;

Path base   = Paths.get("/var/app/uploads").toRealPath();
String name = FilenameUtils.getName(request.getParameter("name"));  // strips dirs
Path target = base.resolve(name).toRealPath();
if (!target.startsWith(base)) {
    throw new SecurityException("path escape");
}
return Files.readAllBytes(target);
```

If you can't take Commons-IO as a dependency, hand-roll the strip
with `Paths.get(name).getFileName()`.

## References

- [OWASP Java Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_System_Cheat_Sheet.html)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
