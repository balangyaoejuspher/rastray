# RSTR-NEXT-001 — Next.js Prisma destructive call with bare id

## Summary

A Next.js file (page, server action, route handler, or any module
inside a project that depends on `next`) calls a destructive Prisma
operation with a **bare identifier** as the `id`:
`prisma.user.delete({ where: { id: id } })`. The bare-id form
skips type coercion *and* ownership scoping. Either the value
was destructured from `context.query`, `params`, the request
body, or a server-action input — any of which a caller can
supply at will.

The fix is two parts: coerce / validate the input, *and* scope
the operation by the caller's identity before letting Prisma
run.

## Severity

`High`.

## Languages

TypeScript, JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mts`,
`.cts`) inside a project whose `package.json` lists `next`.

## What rastray flags

```typescript
// app/users/[id]/page.tsx
export default async function Page({ params }: { params: { id: string } }) {
    const { id } = params;
    return prisma.user.delete({ where: { id: id } });   // ← flagged
}

// app/actions.ts
'use server';
export async function deleteAccount({ id }: { id: string }) {
    return prisma.order.update({ where: { id }, data: { archived: true } }); // ← flagged
}

// app/api/users/route.ts
export async function DELETE(req: Request) {
    const { id } = await req.json();
    return prisma.user.findUniqueOrThrow({ where: { id } });   // ← flagged
}
```

The flagged Prisma operations are the destructive single-record
ones: `delete`, `update`, `findUnique`, `findUniqueOrThrow`,
`findFirst`, `findFirstOrThrow`. Bulk reads (`findMany`,
`count`) are intentionally not flagged.

## What rastray deliberately does *not* flag

Explicit coercion at the call site:

```typescript
prisma.user.delete({ where: { id: Number(id) } });
prisma.user.delete({ where: { id: parseInt(id, 10) } });
prisma.user.delete({ where: { id: BigInt(id) } });
prisma.user.delete({ where: { id: +id } });
```

Qualified accesses (the rule matches a *bare* identifier only):

```typescript
prisma.user.delete({ where: { id: context.query.id } });
prisma.user.delete({ where: { id: session.user.id } });
prisma.user.delete({ where: { id: dto.userId } });
```

Read-many operations:

```typescript
prisma.user.findMany({ where: { id } });
prisma.user.count({ where: { id } });
```

## How to fix it

In `getServerSideProps` / `getStaticProps`, coerce explicitly:

```typescript
export async function getServerSideProps(context) {
    const id = Number(context.query.id);
    if (!Number.isFinite(id)) return { notFound: true };
    const session = await getServerSession(authOptions);
    if (!session) return { notFound: true };
    const user = await prisma.user.findUnique({
        where: { id, ownerId: session.user.id },
    });
    return { props: { user } };
}
```

In a server action or route handler, parse and validate the
input with a schema library before letting Prisma touch the
database:

```typescript
'use server';
import { z } from 'zod';
const Input = z.object({ id: z.string().uuid() });

export async function deleteAccount(raw: unknown) {
    const { id } = Input.parse(raw);
    const session = await auth();
    if (!session) throw new Error('unauthenticated');
    return prisma.user.delete({
        where: { id, ownerId: session.user.id },
    });
}
```

The `ownerId: session.user.id` part is the load-bearing one —
coercion alone fixes the `400 Bad Request` symptom but leaves
the broken-access-control bug.

## How to suppress

If a call is genuinely safe (admin endpoint with caller scoping
done in middleware, audited), suppress per-line:

```typescript
// rastray-ignore: RSTR-NEXT-001 — admin-only route, ownership enforced by middleware
prisma.user.delete({ where: { id: id } });
```

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639 — Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [Next.js — Server Actions and Mutations](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations)
- [Prisma — Filter by composite keys](https://www.prisma.io/docs/concepts/components/prisma-client/composite-types)
