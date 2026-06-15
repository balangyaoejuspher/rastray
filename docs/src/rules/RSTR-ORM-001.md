# RSTR-ORM-001 — Node ORM Model.create(req.body)

## Summary

A Node ORM (Mongoose, Sequelize, Prisma, etc.) is asked to
create or update a record using the entire request body as
the data object. **Mass-assignment**: every field name the
attacker sends becomes a field in the database write.
Submit `{name: "alice", isAdmin: true, role: "admin"}` and
you get an admin account.

## Severity

`High`.

## Languages

JavaScript / TypeScript.

## How to fix it

Allow-list the fields explicitly. Three idiomatic forms:

**lodash.pick:**

```js
import _ from 'lodash';
const data = _.pick(req.body, ['name', 'email']);
await User.create(data);
```

**Schema validation (zod):**

```js
import { z } from 'zod';
const Body = z.object({ name: z.string(), email: z.string().email() }).strict();
const data = Body.parse(req.body);
await User.create(data);
```

**Prisma — only pass the fields explicitly:**

```js
await prisma.user.create({
  data: { name: req.body.name, email: req.body.email },
});
```

## References

- [OWASP: Mass assignment cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [GitHub-Rails mass-assignment incident (2012)](https://github.com/rails/rails/issues/5228)
