# RSTR-SSTI-001 — Python render_template_string / Template(req.x)

## Summary

User input becomes the **template source** itself, not the
data rendered by a static template. Jinja2 and the Python
`string.Template` family give the template author the power
to execute Python expressions; if the attacker writes the
template, the attacker runs Python on the server.

SSTI commonly escalates to **remote code execution** via the
classic payload:

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

…which walks Python's class hierarchy to find subclasses
like `subprocess.Popen` and execute shell commands.

## Severity

`High`.

## Languages

Python.

## What rastray flags

- `Template(request.x)` (constructor takes user input)
- `jinja2.Template(request.x)`
- `render_template_string(request.x)` (Flask convenience)
- `env.from_string(request.x)` (Jinja2 Environment)

## How to fix it

Load templates from disk and pass user input as **data**:

```python
# SAFE — the template is a static file, user input is a variable
return render_template('home.html', name=request.args.get('name'))
```

```html
{# templates/home.html #}
<h1>Hello, {{ name }}</h1>   {# auto-escaped #}
```

`render_template` (no `_string`) is the safe sibling. The
template author and the request submitter must be different
people.

## References

- [PortSwigger: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [CVE-2016-10745: Jinja2 SSTI in Flask docs](https://nvd.nist.gov/vuln/detail/CVE-2016-10745)
- [Black Hat talk: SSTI in popular template engines](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App.pdf)
