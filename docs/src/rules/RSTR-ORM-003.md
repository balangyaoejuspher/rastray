# RSTR-ORM-003 — Rails `create` / `update` with raw `params`

## Summary

A Rails controller spreads `params` (or a nested params hash) into
ActiveRecord `create` / `update` without going through Strong
Parameters' `permit`. Every attribute in the request becomes a column
write, allowing an attacker to flip `admin: true` or any other
unintended field.

This is the original mass-assignment bug class that pushed Rails to
introduce Strong Parameters in the first place.

## Severity

`High`.

## Languages

Ruby (Rails).

## What rastray flags

```ruby
def create
  User.create(params[:user])           # ← flagged
end

def update
  @article.update(params[:article])    # ← flagged
end
```

## What rastray deliberately does *not* flag

- `params.require(:user).permit(:email, :password)` (Strong Parameters).
- `params.permit(:email)` form.
- Direct assignment of individual attributes: `User.create(email: params[:user][:email])`.

## How to fix it

Use Strong Parameters with an explicit allow-list per controller:

```ruby
class UsersController < ApplicationController
  def create
    User.create(user_params)
  end

  private

  def user_params
    params.require(:user).permit(:email, :password)
    # NEVER :is_admin, :role, :verified — those mutate via separate
    # admin-only controllers
  end
end
```

For nested associations, `permit` them explicitly:

```ruby
params.require(:order).permit(:item_id, addresses_attributes: [:street, :zip])
```

## References

- [Rails Guides: Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)
- [Rails mass-assignment history](https://github.com/rails/rails/issues/5228) (the original Egor Homakov incident)
- [CWE-915](https://cwe.mitre.org/data/definitions/915.html)
