# RSTR-INJ-001 — SQL injection via f-string / template literal

## Summary

SQL is built by interpolating user-controlled values into
a string with Python f-string or JS template-literal
syntax, then passed to a `.execute(...)` / `.query(...)` /
`.executemany(...)` call. This is **SQL injection** — one
of the oldest and still most common high-impact web bugs.

## Severity

`High`.

## Languages

Python, JavaScript / TypeScript.

## What rastray flags

A call to `cursor.execute(...)` / `cursor.executemany(...)`
(Python) or `db.query(...)` / `db.execute(...)` (Node)
whose argument is an f-string or template literal
containing a `{...}` / `${...}` interpolation.

```python
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")   # ← flagged
```

```js
db.query(`SELECT * FROM users WHERE id = ${userId}`);          // ← flagged
```

## How to fix it

Use parameterised queries:

```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```js
db.query('SELECT * FROM users WHERE id = ?', [userId]);
```

Or use an ORM that builds parameterised queries for you
(SQLAlchemy, Django ORM, Prisma, Sequelize).

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [Bobby Tables](https://bobby-tables.com/)
