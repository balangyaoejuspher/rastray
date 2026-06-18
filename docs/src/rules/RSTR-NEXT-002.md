# RSTR-NEXT-002 — server action makes a destructive call without input validation

## Summary

A Next.js file is marked with the `'use server'` directive
(making every exported `async function` a publicly-callable
server action) and contains a destructive Prisma operation
(`delete`, `deleteMany`, `update`, `updateMany`, `create`,
`createMany`, `upsert`), but the file contains **no reference to
any input-validation library** (`zod`, `valibot`, `yup`, `joi`,
`superstruct`, `class-validator`, or a `.parse(` /
`safeParse` call).

Server actions are public HTTP endpoints. Browsers can call them
with arbitrary JSON. Skipping schema validation means the action
trusts its parameters' types and shapes — and that's a CVE
waiting to happen the first time a caller sends a non-string
where a string was expected, or extra fields a Prisma `create`
will happily persist.

## Severity

`High`.

## Languages

TypeScript, JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mts`,
`.cts`) inside a project whose `package.json` lists `next`.

## What rastray flags

```typescript
'use server';

export async function deleteAccount(input: { id: string }) {
    return prisma.user.delete({ where: { id: input.id } });       // ← flagged at 'use server' line
}

export async function patchProfile(input: { id: string; name?: string }) {
    return prisma.user.update({
        where: { id: input.id },
        data: { name: input.name },                                // ← flagged: extra fields will be persisted
    });
}
```

## What rastray deliberately does *not* flag

Server actions that use any of the supported validation libraries:

```typescript
'use server';
import { z } from 'zod';
const Schema = z.object({ id: z.string().uuid() });

export async function deleteAccount(input: unknown) {
    const { id } = Schema.parse(input);
    return prisma.user.delete({ where: { id } });
}
```

Read-only server actions (no destructive sink):

```typescript
'use server';
export async function getProfile(id: string) {
    return prisma.user.findMany({ where: { id } });
}
```

Non-server-action files (no `'use server'` directive):

```typescript
// lib/helpers.ts — internal helper, not a public action
export async function purge(id: string) {
    return prisma.user.delete({ where: { id } });
}
```

Validation library detection covers: `zod`, `valibot`, `yup`,
`joi`, `superstruct`, `class-validator`, `safeParse`, and any
`.parse(` call (which catches all the above plus custom
schemas).

## How to fix it

Validate every action parameter with a schema library before
letting Prisma touch the database:

```typescript
'use server';
import { z } from 'zod';

const DeleteInput = z.object({
    id: z.string().uuid(),
});

export async function deleteAccount(raw: unknown) {
    const { id } = DeleteInput.parse(raw);
    const session = await auth();
    if (!session) throw new Error('unauthenticated');
    return prisma.user.delete({
        where: { id, ownerId: session.user.id },
    });
}
```

`parse` throws on invalid input — exactly what you want from a
server action. Use `safeParse` if you'd rather return a typed
error object.

## How to suppress

If a server action genuinely needs no parameter validation
(e.g. a parameter-less revalidation trigger), suppress at the
directive line:

```typescript
// rastray-ignore: RSTR-NEXT-002 — parameter-less revalidation only
'use server';

export async function revalidate() {
    revalidatePath('/');
}
```

## References

- [Next.js — Server Actions and Mutations](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations)
- [Zod documentation](https://zod.dev/)
- [OWASP A04:2021 — Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
