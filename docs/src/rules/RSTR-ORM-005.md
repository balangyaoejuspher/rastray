# RSTR-ORM-005 — Rails `params.require(:x).permit!` (open permit)

## Summary

`params.require(:x).permit!` declares "every key inside `params[:x]` is
permitted." It is the open-door form of Rails Strong Parameters — the
exact thing Strong Parameters was introduced to prevent. Any attribute
the attacker submits (including `is_admin: true`, `role: 'owner'`,
`verified: true`) becomes a model write.

This is the same vulnerability class as [`RSTR-ORM-003`](./RSTR-ORM-003.md),
expressed via the `permit!` escape hatch instead of by skipping
Strong Parameters entirely.

## Severity

`High`.

## Languages

Ruby (Rails).

## What rastray flags

```ruby
def user_params
  params.require(:user).permit!                       # ← flagged
end
```

```ruby
params.permit!                                         # ← flagged
```

## What rastray deliberately does *not* flag

Explicit allow-list:

```ruby
def user_params
  params.require(:user).permit(:email, :first_name, :last_name)
end
```

Nested allow-list:

```ruby
def order_params
  params.require(:order).permit(:item_id, addresses_attributes: [:street, :zip])
end
```

## How to fix it

Enumerate the attributes you actually want to accept. Anything not in
the list is silently dropped, which is exactly the behaviour you want:

```ruby
def user_params
  params.require(:user).permit(:email, :first_name, :last_name)
  # NEVER :is_admin, :role, :verified — those mutate via separate
  # admin-only controllers
end
```

For nested associations, list the inner keys:

```ruby
def order_params
  params
    .require(:order)
    .permit(:item_id, :quantity, addresses_attributes: [:street, :city, :zip])
end
```

If the controller is *truly* internal (e.g. it talks to its own
admin UI behind authentication you control), `permit!` is still
unsafe — the underlying model usually has columns the admin UI
should not be able to flip either. Always enumerate.

## References

- [Rails Guides: Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)
- [Rails Security Guide: Mass Assignment](https://guides.rubyonrails.org/security.html#mass-assignment)
- [CWE-915](https://cwe.mitre.org/data/definitions/915.html)
