# RSTR-RDR-003 — Go `http.Redirect` with request input

## Summary

Go counterpart of [`RSTR-RDR-002`](./RSTR-RDR-002.md). A handler
redirects to a URL read from `r.FormValue` or `r.URL.Query().Get`
without checking the host or scheme.

## Severity

`Medium`.

## Languages

Go.

## What rastray flags

```go
func postLogin(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r,
        r.URL.Query().Get("next"),                       // ← flagged
        http.StatusFound)
}
```

## What rastray deliberately does *not* flag

- Redirects to literal paths.
- Redirects whose target was assembled via `url.URL{Path: ...}` from
  validated components.

## How to fix it

Reject absolute URLs and enforce an allow-list:

```go
var allowedHosts = map[string]struct{}{
    "app.example.com": {},
}

func safeRedirect(w http.ResponseWriter, r *http.Request, raw string) {
    u, err := url.Parse(raw)
    if err != nil {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }
    // Relative paths only? Or allow-listed external hosts.
    if u.Host == "" || allowedHosts[u.Host] != struct{}{} {
        // host empty => relative; or explicitly trusted
    } else {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }
    http.Redirect(w, r, raw, http.StatusFound)
}
```

For most apps the simpler rule — *only allow redirects whose target
starts with `/` and is not `//` (protocol-relative)* — is enough:

```go
target := r.URL.Query().Get("next")
if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
    target = "/"
}
http.Redirect(w, r, target, http.StatusFound)
```

## References

- [OWASP Unvalidated Redirects Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601](https://cwe.mitre.org/data/definitions/601.html)
