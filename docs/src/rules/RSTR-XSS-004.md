# RSTR-XSS-004 — Flask `Markup(...)` / direct return with request input

## Summary

A Flask handler returns request input as part of the HTTP response
without HTML-escaping it, either by wrapping it in `Markup(...)` (which
disables Jinja's auto-escaping) or by returning the value as part of a
hand-built HTML string.

The browser parses the response in the application's origin, so any
HTML the attacker submits — including `<script>` tags or event
handlers — runs there.

## Severity

`High`.

## Languages

Python (Flask / Quart).

## What rastray flags

```python
@app.route('/echo')
def echo():
    return Markup(f'<h1>{request.args["msg"]}</h1>')     # ← flagged

@app.route('/raw')
def raw():
    return '<p>Hi, ' + request.args['name'] + '</p>'     # ← flagged
```

## What rastray deliberately does *not* flag

- `return render_template('echo.html', msg=request.args['msg'])` — Jinja
  auto-escapes by default.
- Values returned through `jsonify(...)` — JSON, not HTML.
- Values explicitly passed through `markupsafe.escape(...)` first.

## How to fix it

Use Jinja templates and let auto-escaping handle the data:

```python
# templates/echo.html
# <h1>{{ msg }}</h1>

@app.route('/echo')
def echo():
    return render_template('echo.html', msg=request.args['msg'])
```

If you need a string response, escape explicitly:

```python
from markupsafe import escape

@app.route('/raw')
def raw():
    return f'<p>Hi, {escape(request.args["name"])}</p>'
```

`Markup(...)` is the *promise* "I have already escaped this; treat it
as trusted HTML." Only use it on values you yourself produced from
safe sources.

## References

- [Flask: Security Considerations — Cross-Site Scripting](https://flask.palletsprojects.com/en/stable/security/#cross-site-scripting-xss)
- [Jinja autoescaping](https://jinja.palletsprojects.com/en/stable/api/#autoescaping)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
