# RSTR-SSRF-004 — Go `http.Get` / `http.NewRequest` with request input

## Summary

Go equivalent of [`RSTR-SSRF-001`](./RSTR-SSRF-001.md). A handler
issues an outbound HTTP call where the URL is read from the request via
`r.FormValue` / `r.URL.Query().Get` / `mux.Vars(r)`.

## Severity

`High`.

## Languages

Go.

## What rastray flags

`http.Get`, `http.Head`, `http.Post`, `http.PostForm`, `http.NewRequest`,
and `http.NewRequestWithContext` when the URL argument is fed directly
by `r.FormValue(...)`, `r.URL.Query().Get(...)`, or similar request
accessors:

```go
func proxy(w http.ResponseWriter, r *http.Request) {
    resp, err := http.Get(r.URL.Query().Get("url"))   // ← flagged
    ...
}
```

```go
req, _ := http.NewRequest("POST",
    r.FormValue("target"), body)                       // ← flagged
```

## What rastray deliberately does *not* flag

- Literal URLs.
- A URL stored in an intermediate variable.
- URLs built via `url.URL{Scheme:"https", Host: ALLOWED_HOST, Path: ...}`
  where only the path comes from the request.

## How to fix it

Allow-list the destination host and block private/metadata IPs:

```go
var allowed = map[string]struct{}{
    "api.example.com": {},
    "cdn.example.com": {},
}

func safeGet(raw string) (*http.Response, error) {
    u, err := url.Parse(raw)
    if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
        return nil, errors.New("bad url")
    }
    if _, ok := allowed[u.Hostname()]; !ok {
        return nil, errors.New("host not allowed")
    }
    addrs, err := net.LookupIP(u.Hostname())
    if err != nil {
        return nil, err
    }
    for _, ip := range addrs {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return nil, errors.New("private destination")
        }
    }
    client := &http.Client{
        Timeout: 5 * time.Second,
        CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
            return http.ErrUseLastResponse  // do not follow
        },
    }
    return client.Get(raw)
}
```

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
