# RSTR-CSRF-002 — Django `@csrf_exempt` on a state-changing view

## Summary

A Django view is decorated with `@csrf_exempt`, removing the CSRF
protection that the rest of the project's middleware enforces. If the
view accepts `POST` / `PUT` / `PATCH` / `DELETE`, any cross-site form
submission targeting it succeeds with the victim's session cookies
attached.

## Severity

`Medium`. The bug is real but limited to the single view; the rest of
the application is still protected.

## Languages

Python.

## What rastray flags

Any use of the `csrf_exempt` decorator from `django.views.decorators.csrf`:

```python
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt                                          # ← flagged
def transfer_funds(request):
    ...
```

```python
@csrf_exempt                                          # ← flagged
@require_POST
def webhook(request):
    ...
```

## What rastray deliberately does *not* flag

- Class-based views protected by Django's default CSRF middleware.
- Views with `@requires_csrf_token` or `@ensure_csrf_cookie`.

## How to fix it

**For internal endpoints**: remove `@csrf_exempt`. Let the middleware
enforce the token; if the client is a SPA, expose the token via
`{% csrf_token %}` or `ensure_csrf_cookie` and send it back as
`X-CSRFToken`.

**For third-party webhooks** (Stripe, GitHub, Slack, etc.): verify the
incoming signature instead of disabling CSRF. The signature does the
job that the CSRF token does for browser-originated requests.

```python
@csrf_exempt
@require_POST
def stripe_webhook(request):
    sig = request.META.get('HTTP_STRIPE_SIGNATURE', '')
    try:
        event = stripe.Webhook.construct_event(
            request.body, sig, settings.STRIPE_WEBHOOK_SECRET
        )
    except (ValueError, stripe.error.SignatureVerificationError):
        return HttpResponseBadRequest()
    ...
```

The `csrf_exempt` is unavoidable in that case — suppress it with a
comment explaining the signature check substitutes for the missing
CSRF protection:

```python
# rastray-ignore: RSTR-CSRF-002 — Stripe webhook; signature verified above
@csrf_exempt
@require_POST
def stripe_webhook(request): ...
```

## References

- [Django CSRF docs — `csrf_exempt`](https://docs.djangoproject.com/en/stable/ref/csrf/#django.views.decorators.csrf.csrf_exempt)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
