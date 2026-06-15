# RSTR-ORM-002 — Django ORM `create`/`filter`/`update` with `**request.POST`

## Summary

A Django view passes a request body directly into a model `create` /
`update` / `filter`, e.g. `Model.objects.create(**request.POST)`. Every
key in the request body becomes a field write, regardless of whether
the form was meant to expose it. An attacker can promote themselves to
admin by submitting `is_staff=true` (or whatever the model's flag
field is called).

This is **mass assignment**, CWE-915.

## Severity

`High`.

## Languages

Python (Django).

## What rastray flags

```python
def signup(request):
    User.objects.create(**request.POST)              # ← flagged
```

```python
def update(request, pk):
    Article.objects.filter(pk=pk).update(**request.POST)  # ← flagged
```

## What rastray deliberately does *not* flag

- Form-bound paths: `form = SignupForm(request.POST); form.save()`.
- ModelForm or DRF Serializer-driven updates.
- Explicit field lists: `User.objects.create(email=request.POST['email'])`.

## How to fix it

Always go through a `ModelForm`, a Django REST Framework `Serializer`,
or an explicit allow-list:

```python
from django.forms import ModelForm

class SignupForm(ModelForm):
    class Meta:
        model = User
        fields = ['email', 'password']     # allow-list

def signup(request):
    form = SignupForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest(form.errors)
    form.save()
```

```python
# REST framework
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        read_only_fields = ['is_staff', 'is_superuser']
```

## References

- [Django docs — `ModelForm`](https://docs.djangoproject.com/en/stable/topics/forms/modelforms/)
- [DRF Serializers — `read_only_fields`](https://www.django-rest-framework.org/api-guide/serializers/#specifying-read-only-fields)
- [OWASP API Security Top 10 — API3: Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
