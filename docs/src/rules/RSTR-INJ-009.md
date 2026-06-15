# RSTR-INJ-009 — Rails `params[:x].constantize` / `.classify` / `.safe_constantize`

## Summary

A Rails handler resolves a class by calling `.constantize`,
`.safe_constantize`, or `.classify` on a request parameter. An attacker
who controls the string can instantiate **any class in the autoload
namespace** — including ones whose `initialize` / `_load` / `inherited`
hooks have dangerous side effects. The "mobile API" pattern of
"deserialize whatever class the client names" historically led to RCE
via gadget chains in several published Rails advisories.

## Severity

`High`.

## Languages

Ruby (Rails).

## What rastray flags

```ruby
model = params[:class].constantize                  # ← flagged
klass = params[:kind].safe_constantize              # ← flagged
model = params[:type].classify                      # ← flagged
```

## What rastray deliberately does *not* flag

Allow-list resolution:

```ruby
ALLOWED = { 'user' => User, 'admin' => AdminUser, 'guest' => GuestUser }
klass = ALLOWED.fetch(params[:kind]) { raise ActionController::BadRequest }
```

```ruby
klass = case params[:kind]
        when 'user'  then User
        when 'admin' then AdminUser
        end
```

`.constantize` on a constant or a non-`params` source is also not
flagged.

## How to fix it

Resolve through an allow-list. The hash-with-fetch idiom above is the
canonical pattern; the case-statement form is equally fine. Both
ensure only classes the developer intended are reachable.

If the parameter is *supposed* to be one of a small fixed set, just
do an explicit comparison rather than reflection:

```ruby
if %w[user admin guest].include?(params[:kind])
  # safe to use params[:kind] in a query, but still construct
  # the class explicitly elsewhere
end
```

## References

- [Rails Guides: Mass Assignment & dynamic dispatch](https://guides.rubyonrails.org/security.html)
- [HackerOne: classic Rails Marshal exploit](https://hackerone.com/reports/473596)
- [CWE-470: Use of Externally-Controlled Input to Select Classes or Code](https://cwe.mitre.org/data/definitions/470.html)
