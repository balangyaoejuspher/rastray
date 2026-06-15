# RSTR-INJ-010 — Rails `render inline:` / `text:` with `params` interpolation

## Summary

A Rails controller calls `render` with `inline:` (or the deprecated
`text:`) and the supplied string contains a `#{params[...]}`
interpolation. Ruby substitutes the request value into the template
source *before* the renderer parses it, so the attacker controls the
template — server-side template injection (SSTI), which usually
escalates to RCE through ERB's `<%= ... %>` evaluation.

## Severity

`Critical`.

## Languages

Ruby (Rails).

## What rastray flags

```ruby
render inline: "<h1>Hi #{params[:name]}</h1>"             # ← flagged
render(text: "Hello #{params[:name]}")                    # ← flagged
render inline_template: "<%= #{params[:expr]} %>"         # ← flagged
```

## What rastray deliberately does *not* flag

Render a fixed template and pass user input as `locals:`:

```ruby
render :show, locals: { name: params[:name] }             # safe
render template: 'users/show', locals: { name: params[:name] }   # safe
```

## How to fix it

Always render a template that ships with the application; never let
user input become the template source. Pass values as `locals:` and
let ERB's auto-escaping handle the output:

```ruby
# app/views/users/show.html.erb
# <h1>Hi <%= name %></h1>

def show
  render :show, locals: { name: params[:name] }
end
```

For one-off responses, render plain strings without interpolation:

```ruby
render plain: "Hello, #{ERB::Util.h(params[:name])}"      # also flagged but safe
```

Even the plain-string form above is still flagged because the rule
cannot prove the escape is correct; if you adopt that pattern
intentionally, suppress per-line.

## References

- [Rails Guides: Layouts and Rendering](https://guides.rubyonrails.org/layouts_and_rendering.html#using-render)
- [PortSwigger: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)
