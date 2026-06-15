# RSTR-INJ-008 — Rails `.where("... #{params[...]} ...")`

## Summary

A Rails ActiveRecord query method (`.where`, `.find_by_sql`,
`.update_all`, `.delete_all`, etc.) is called with a string-interpolated
SQL fragment that contains `params[...]`. Ruby evaluates the `#{...}`
substitution *before* the string reaches ActiveRecord, so the database
sees an attacker-controlled query — classic SQL injection.

ActiveRecord's hash form (`.where(id: params[:id])`) and the positional
form (`.where("id = ?", params[:id])`) both delegate to prepared
statements and are safe.

## Severity

`Critical`.

## Languages

Ruby (Rails).

## What rastray flags

```ruby
User.where("id = '#{params[:user][:id]}'")                # ← flagged
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")  # ← flagged
Order.update_all("status = '#{params[:s]}'")              # ← flagged
```

## What rastray deliberately does *not* flag

Safe ActiveRecord forms:

```ruby
User.where(id: params[:id])                                  # hash form
User.where("id = ?", params[:id])                            # positional
User.where("id = :id", id: params[:id])                      # named
```

These compile to prepared statements; the value never reaches the SQL
parser as code.

## How to fix it

Use one of the two parameterised forms:

```ruby
# Hash form (preferred when matching one column)
User.where(id: params[:id])

# Positional form (when you need a custom predicate)
User.where("name LIKE ?", "%#{params[:q]}%")

# Named placeholders for multi-column queries
User.where("name LIKE :q OR email LIKE :q", q: "%#{params[:q]}%")
```

For more complex queries, build the query progressively:

```ruby
scope = User.all
scope = scope.where(role: params[:role])        if params[:role].present?
scope = scope.where("created_at >= ?", since)   if since.present?
scope.order(:name)
```

Even when the value looks "safe" (a number, a UUID), use the
parameterised form. Type coercion happens at the binding layer and
removes any ambiguity.

## References

- [Rails Guides: SQL Injection](https://guides.rubyonrails.org/security.html#sql-injection)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
