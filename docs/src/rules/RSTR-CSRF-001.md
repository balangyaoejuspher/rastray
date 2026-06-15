# RSTR-CSRF-001 — Flask WTF_CSRF_ENABLED disabled

## Summary

Flask-WTF's CSRF protection is disabled globally
(`WTF_CSRF_ENABLED = False` or `app.config['WTF_CSRF_ENABLED']
= False`). Every state-changing form in the app is now
vulnerable to cross-site request forgery: an attacker who
gets the victim to visit a page they control can submit a
form to your app using the victim's cookies.

## Severity

`High`.

## Languages

Python.

## How to fix it

Leave the default in place — `WTF_CSRF_ENABLED` defaults to
`True` for a reason. Use `{{ csrf_token() }}` in every form:

```html
<form method="POST" action="/profile">
  {{ csrf_token() }}
  <input name="name" />
  <button type="submit">Save</button>
</form>
```

For AJAX, set the `X-CSRFToken` header from
`{{ csrf_token() }}` injected into a `<meta>` tag.

If a specific webhook handler legitimately can't have CSRF
protection (e.g. Stripe webhook), exempt that one route:

```python
@csrf.exempt
@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    # verify Stripe signature instead
    ...
```

…not the whole app.

## References

- [Flask-WTF: CSRF protection](https://flask-wtf.readthedocs.io/en/1.2.x/csrf/)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html)
