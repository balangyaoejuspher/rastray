# RSTR-NEST-002 — NestJS controller exposes a mutation without any guard

## Summary

A NestJS controller declares at least one mutation handler
(`@Post`, `@Put`, `@Patch`, or `@Delete`) but the file contains
**no guard decorator at all** — no `@UseGuards`, no `@Roles`,
no `@Auth`, no `@Public()` marker. Either the route is
unauthenticated (and the team forgot), or it is authenticated
by middleware too distant from the handler for a reviewer to
verify by reading the file.

Both cases are a problem. Mutation routes need the auth decision
visible at the route definition; pentest and code-review tools
look at the controller, not five files away in a `main.ts`
pipeline.

## Severity

`High`.

## Languages

TypeScript, JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mts`, `.cts`)
inside a project whose `package.json` lists `@nestjs/core` or
`@nestjs/common`.

## What rastray flags

```typescript
@Controller('users')
export class UsersController {
    @Post()
    create(@Body() dto: CreateUserDto) {}                     // ← flagged at @Controller line

    @Delete(':id')
    remove(@Param('id') id: string) {}
}
```

```typescript
@Controller('admin')
export class AdminController {
    @Patch('config')
    update(@Body() patch: ConfigPatch) {}                     // ← flagged at @Controller line
}
```

## What rastray deliberately does *not* flag

Any guard decorator anywhere in the file silences the check:

```typescript
@UseGuards(AuthGuard('jwt'))
@Controller('users')
export class UsersController {
    @Post() create() {}
}
```

Projects that register a global guard via `APP_GUARD` in any
`*.module.ts` are auto-detected and silenced for the entire
project — no per-controller suppression needed:

```typescript
// app.module.ts
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/jwt-auth.guard';

@Module({
    providers: [
        { provide: APP_GUARD, useClass: JwtAuthGuard },
    ],
})
export class AppModule {}
```

With the above in place, every controller in the project is
treated as globally guarded; this rule does not fire on any of
them. This matches the dominant production pattern (auth wired
once at the module root, not repeated on every controller).

```typescript
@Controller('users')
@Roles('admin')
export class UsersController {
    @Post() create() {}
}
```

Per-handler guards are also accepted:

```typescript
@Controller('users')
export class UsersController {
    @UseGuards(AuthGuard('jwt'))
    @Post()
    create() {}
}
```

Read-only controllers (no `@Post`/`@Put`/`@Patch`/`@Delete`) are
never flagged, because the threat model is mutation-shaped:

```typescript
@Controller('health')
export class HealthController {
    @Get() ping() { return { ok: true }; }
}
```

Routes that are *intentionally* public should declare it explicitly
with `@Public()` so future readers and your guard pipeline both
know it on sight:

```typescript
@Controller('webhooks')
export class WebhooksController {
    @Public()
    @Post()
    receive(@Body() body: any) {}
}
```

## How to fix it

The two-line fix is to apply a guard at the controller level:

```typescript
@UseGuards(AuthGuard('jwt'))
@Controller('users')
export class UsersController {
    @Post()
    create(@Body() dto: CreateUserDto) {}
}
```

For role-based access:

```typescript
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Controller('users')
export class UsersController {
    @Roles('admin')
    @Delete(':id')
    remove(@Param('id') id: string) {}
}
```

If you have a global guard registered in `AppModule.providers`
that already covers this controller, add a comment at the
controller line so a reviewer doesn't have to chase it:

```typescript
// rastray-ignore: RSTR-NEST-002 — globally guarded via APP_GUARD JwtAuthGuard
@Controller('users')
export class UsersController { ... }
```

## How to suppress

Per-line suppression at the `@Controller(` line when the controller
is genuinely public or globally guarded:

```typescript
// rastray-ignore: RSTR-NEST-002 — public webhook target, signature verified in middleware
@Controller('webhooks')
export class WebhooksController { ... }
```

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [NestJS Guards documentation](https://docs.nestjs.com/guards)
- [CWE-862 — Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
