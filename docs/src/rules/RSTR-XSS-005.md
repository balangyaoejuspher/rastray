# RSTR-XSS-005 — Go HTTP response writes with request input

## Summary

A Go HTTP handler writes request-derived data into the response with
`fmt.Fprintf`, `io.WriteString`, or `w.Write([]byte(...))` — no HTML
escaping in between. The browser receives the attacker's input as part
of an HTML page rendered in the application's origin.

## Severity

`High`.

## Languages

Go.

## What rastray flags

```go
func hello(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "<h1>Hi %s</h1>",
        r.URL.Query().Get("name"))                  // ← flagged
}
```

```go
io.WriteString(w, "<p>"+r.FormValue("msg")+"</p>") // ← flagged
```

## What rastray deliberately does *not* flag

- Writes that go through `html/template` (auto-escaping).
- `json.NewEncoder(w).Encode(...)` — JSON, not HTML.
- Writes of literal strings.

## How to fix it

Use `html/template` — Go's stdlib renderer is context-aware and escapes
correctly per HTML/JS/URL context:

```go
import "html/template"

var helloTmpl = template.Must(template.New("hi").Parse(
    `<h1>Hi {{ .Name }}</h1>`))

func hello(w http.ResponseWriter, r *http.Request) {
    helloTmpl.Execute(w, struct{ Name string }{r.URL.Query().Get("name")})
}
```

For one-off writes, escape explicitly:

```go
import "html"

fmt.Fprintf(w, "<p>%s</p>", html.EscapeString(r.FormValue("msg")))
```

`text/template` does **not** escape — use it only for non-HTML output.

## References

- [Go `html/template` docs](https://pkg.go.dev/html/template)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
