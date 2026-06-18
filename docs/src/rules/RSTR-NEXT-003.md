# RSTR-NEXT-003 — App Router route handler missing auth reference

## Summary

A Next.js **App Router** route handler file
(`app/**/route.{ts,tsx,js,jsx,mts,cts}`) exports a mutation HTTP
method (`POST`, `PUT`, `PATCH`, or `DELETE`) but the file
contains **no auth helper reference** (`auth()`,
`getServerSession()`, `getToken()`, `currentUser()`,
`getUser()`, `requireAuth()`, `requireSession()`,
`cookies().get(...)`, or `headers().get('authorization')`).

Either the route is unauthenticated (and the team forgot), or
it is authenticated by middleware too distant from the handler
for a reviewer to verify by reading the file. Both cases are a
problem. Mutation routes need the auth decision visible at the
route definition.

## Severity

`Medium`. Lower than `RSTR-NEST-002` because Next.js has more
variance in how auth is wired (some apps gate everything in
`middleware.ts`, which this file-scope check can't see).

## Languages

TypeScript, JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mts`,
`.cts`) inside a project whose `package.json` lists `next`.

## What rastray flags

```typescript
// app/api/users/route.ts
import { NextResponse } from 'next/server';

export async function POST(req: Request) {                           // ← flagged
    const body = await req.json();
    return NextResponse.json({ ok: true });
}
```

```typescript
// app/api/admin/route.ts
export const DELETE = async (req: Request) => {                       // ← flagged
    await prisma.user.deleteMany({ where: { archived: true } });
    return new Response(null, { status: 204 });
};
```

## What rastray deliberately does *not* flag

Routes that call an auth helper anywhere in the file:

```typescript
// app/api/users/route.ts
import { auth } from '@/lib/auth';

export async function DELETE(req: Request) {
    const session = await auth();
    if (!session) return new Response(null, { status: 401 });
    // ...
}
```

Read-only handlers (only `GET` / `HEAD` / `OPTIONS`):

```typescript
// app/api/health/route.ts
export async function GET() {
    return new Response('ok');
}
```

Non-route files (anything not named `route.{ts,tsx,…}` under
an `app/` segment):

```typescript
// lib/api.ts — not a route file
export async function POST() { ... }
```

Pages Router API routes (`pages/api/**`) — the threat model is
the same but the file convention is different, and we may add
`RSTR-NEXT-004` for that pattern later.

The auth-helper detection covers (any one is enough):

- `getServerSession(`, `getToken(`, `currentUser(`, `getUser(`
- `requireAuth(`, `requireSession(`
- `auth(`
- `cookies().get(...)`
- `headers().get('authorization')`

## How to fix it

Call your auth helper at the top of every mutation handler:

```typescript
// app/api/users/route.ts
import { auth } from '@/lib/auth';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
    const session = await auth();
    if (!session) return new Response(null, { status: 401 });
    const body = await req.json();
    // ...
    return NextResponse.json({ ok: true });
}
```

If a route is intentionally public (webhook target, OAuth
callback) and signature-verified later in the handler, suppress
at the mutation export line and explain why.

## How to suppress

Per-line at the mutation export line:

```typescript
// rastray-ignore: RSTR-NEXT-003 — Stripe webhook, signature verified via stripe.webhooks.constructEvent below
export async function POST(req: Request) {
    const sig = req.headers.get('stripe-signature');
    // ...
}
```

## References

- [Next.js — Route Handlers](https://nextjs.org/docs/app/building-your-application/routing/route-handlers)
- [Next.js — Authentication](https://nextjs.org/docs/app/building-your-application/authentication)
- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-862 — Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
