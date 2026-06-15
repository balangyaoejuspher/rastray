# RSTR-ORM-004 — raw SQL template literal

## Summary

A raw SQL query is built by interpolating values into a
template literal (`` `SELECT * FROM users WHERE id = ${id}` ``)
and passed to `knex.raw`, `sequelize.query`, or Prisma's
`$queryRawUnsafe`. The fact that the syntax looks modern
doesn't change the wire format — it's still string
concatenation, and still SQL-injectable.

## Severity

`Critical`. Full database disclosure, and on some configs
RCE via stored procedures or `xp_cmdshell`.

## Languages

JavaScript / TypeScript.

## How to fix it

Use parameter binding:

```js
// Knex
await knex.raw('SELECT * FROM users WHERE id = ?', [id]);

// Sequelize
await sequelize.query('SELECT * FROM users WHERE id = :id', {
  replacements: { id },
  type: sequelize.QueryTypes.SELECT,
});

// Prisma: use $queryRaw (tagged template — auto-parameterised)
// NOT $queryRawUnsafe
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
```

The Prisma case is subtle: `$queryRaw` (tagged template
form) IS safe because Prisma parses the `${...}`
expressions and binds them as parameters. `$queryRawUnsafe`
exists explicitly to bypass that — it's named to discourage
exactly the bug this rule catches.

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Prisma docs: $queryRaw vs $queryRawUnsafe](https://www.prisma.io/docs/orm/prisma-client/queries/raw-database-access/raw-queries)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
