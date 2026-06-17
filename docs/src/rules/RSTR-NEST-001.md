# RSTR-NEST-001 — NestJS Prisma destructive call with bare id

## Summary

A NestJS handler reads an `id` from `@Param('id')` and passes it
straight into a Prisma destructive operation —
`prisma.user.delete({ where: { id: id }})` — without coercion or
ownership validation. Two real problems hide behind that one line:

1. **Type coercion.** `@Param('id')` is a string. Prisma models
   with a numeric `Int` / `BigInt` id will throw at runtime, and
   models with `String` ids accept *any* string the caller sends
   (uuids belonging to other tenants included).
2. **Authorization.** Even if the id type matches, the handler
   never checks that the id belongs to the calling user. Pass any
   id and Prisma happily deletes it.

The fix is two parts: coerce / validate the input *and* scope the
operation by the caller's identity before letting Prisma run.

## Severity

`High`.

## Languages

TypeScript, JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mts`, `.cts`)
inside a project whose `package.json` lists `@nestjs/core` or
`@nestjs/common`.

## What rastray flags

```typescript
@Delete(':id')
remove(@Param('id') id: string) {
    return prisma.user.delete({ where: { id: id } });        // ← flagged
}

@Patch(':id')
patch(@Param('id') id: string) {
    return prisma.user.update({ where: { id: id }, data: { x: 1 } }); // ← flagged
}

@Get(':id')
fetch(@Param('id') id: string) {
    return prisma.user.findUniqueOrThrow({ where: { id: id } });      // ← flagged
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
prisma.user.delete({ where: { id: +id } });
prisma.user.delete({ where: { id: BigInt(id) } });
```

Qualified accesses (the rule matches a *bare* identifier only):

```typescript
prisma.user.delete({ where: { id: req.params.id } });
prisma.user.delete({ where: { id: this.id } });
prisma.user.delete({ where: { id: dto.userId } });
```

`findMany` / `count` reads where the `id` filter is a search field
rather than a destructive lookup:

```typescript
prisma.user.findMany({ where: { id: id } });
prisma.user.count({ where: { id: id } });
```

## How to fix it

Coerce *and* authorize. The idiomatic NestJS form does both with
a pipe and an ownership check:

```typescript
@Delete(':id')
remove(
    @Param('id', ParseIntPipe) id: number,
    @CurrentUser() user: AuthUser,
) {
    return prisma.user.delete({
        where: { id, ownerId: user.id },
    });
}
```

Or with a DTO and class-validator:

```typescript
class UserIdParam {
    @IsUUID()
    id!: string;
}

@Delete(':id')
remove(@Param() params: UserIdParam, @CurrentUser() user: AuthUser) {
    return prisma.userRow.delete({
        where: { id: params.id, ownerId: user.id },
    });
}
```

The `ownerId: user.id` part is the load-bearing one — coercion
alone fixes the `400 Bad Request` symptom but leaves the
broken-access-control bug.

## How to suppress

If a call is genuinely safe (admin endpoint with caller scoping
done elsewhere, audited), suppress per-line:

```typescript
// rastray-ignore: RSTR-NEST-001 — admin-only route, ownership enforced by RouteGuard at module level
prisma.user.delete({ where: { id: id } });
```

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639 — Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [NestJS — ParseIntPipe](https://docs.nestjs.com/pipes#built-in-pipes)
- [Prisma — uniqueness constraints](https://www.prisma.io/docs/concepts/components/prisma-schema/data-model#defining-a-unique-field)
