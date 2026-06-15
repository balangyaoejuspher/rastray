# RSTR-RDR-004 — Rails `redirect_to params[:x]`

## Summary

A Rails controller calls `redirect_to` with a value taken directly
from `params[...]`. An attacker submits
`?next=https://phish.example` and the user sees a trusted-looking
link that lands on the attacker's page after the redirect.

This is the Rails counterpart of
[`RSTR-RDR-002`](./RSTR-RDR-002.md) (Flask/Django) and
[`RSTR-RDR-003`](./RSTR-RDR-003.md) (Go).

Recent Rails versions (5.0+) refuse cross-origin redirects by
default (`ActionController::Redirecting::UnsafeRedirectError`), but
*same-origin* phishing — `/login?next=/admin/transfer?to=evil` —
still succeeds. Always validate.

## Severity

`Medium`.

## Languages

Ruby (Rails).

## What rastray flags

```ruby
def callback
  redirect_to params[:next]                   # ← flagged
end
```

```ruby
redirect_to params[:url]                       # ← flagged
```

## What rastray deliberately does *not* flag

Named route helpers and constant strings:

```ruby
redirect_to dashboard_path                    # safe
redirect_to user_path(@user)                  # safe
redirect_to '/login'                          # safe
```

Indirect flow (`path = params[:next]; redirect_to path`) is also not
flagged — the same one-step taint scope used everywhere in rastray.

## How to fix it

Allow-list the target. The simplest pattern uses a per-controller
helper that returns either a sanitised path or a safe default:

```ruby
class SessionsController < ApplicationController
  def create
    # ... authenticate ...
    redirect_to safe_next_path
  end

  private

  def safe_next_path
    candidate = params[:next].to_s
    return dashboard_path if candidate.blank?

    # only allow same-origin, leading-slash, non-protocol-relative
    uri = URI.parse(candidate) rescue nil
    return dashboard_path unless uri && uri.host.nil? && candidate.start_with?('/')
    return dashboard_path if candidate.start_with?('//')

    candidate
  end
end
```

For redirects to an external site, maintain an explicit allow-list
of trusted hosts.

## References

- [Rails Guides: Redirection](https://guides.rubyonrails.org/action_controller_overview.html#sending-files)
- [OWASP Unvalidated Redirects Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601](https://cwe.mitre.org/data/definitions/601.html)
