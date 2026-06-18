# RSTR-SPRING-001 — Spring Security allows unauthenticated access to a broad path

## Summary

A Spring Security `SecurityFilterChain` (or legacy
`WebSecurityConfigurerAdapter`) chains `permitAll()` onto a
broad path matcher: `/**`, `/api/**`, `/api/v{n}/**`,
`/v{n}/**`, `/services/**`, or `/rest/**`. Every endpoint under
that prefix becomes reachable without authentication, including:

- endpoints added later by other teams (today's "public health
  check" path becomes tomorrow's "admin metrics" path under the
  same prefix)
- mutation endpoints (`POST /api/users`, `DELETE /api/orders/{id}`)
  that an attacker can invoke directly
- internal endpoints that were never intended to be on the public
  surface (`/api/internal/...`, `/api/_debug/...`)

The intended Spring Security pattern is "deny by default" — a
small allow-list of explicit public endpoints, then
`.anyRequest().authenticated()`. The flagged pattern inverts
this into "allow by default".

## Severity

`High`.

## Languages

Java (`.java`) and Kotlin (`.kt`) inside a project whose
Maven/Gradle manifest declares `spring-boot-starter` or
`org.springframework.boot`.

## What rastray flags

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/**").permitAll()              // ← flagged
    );
    return http.build();
}
```

Also flagged:

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/**").permitAll()              // ← flagged
);
```

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/v1/**").permitAll()           // ← flagged
);
```

Legacy `antMatchers` / `mvcMatchers` form:

```java
http.authorizeRequests()
    .antMatchers("/api/**").permitAll()                  // ← flagged
    .anyRequest().authenticated();
```

## What rastray deliberately does *not* flag

`permitAll()` scoped to specific public endpoints:

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
    .requestMatchers("/actuator/health").permitAll()
    .anyRequest().authenticated()
);
```

Path-scoped role checks:

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/api/**").authenticated()
);
```

`permitAll()` chained onto a *different* matcher in a sibling
clause is not falsely attributed to a broad matcher in the same
configuration block. The detection only fires when `permitAll()`
is directly chained onto a broad-path matcher call.

Static resource matchers (`PathRequest.toStaticResources()...`)
and the `H2` console matcher are also not flagged — they don't
match the broad-path pattern.

## How to fix it

Replace the broad `permitAll()` with an explicit allow-list:

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(
                "/api/auth/login",
                "/api/auth/register",
                "/api/auth/refresh"
            ).permitAll()
            .requestMatchers("/actuator/health", "/actuator/info").permitAll()
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
    return http.build();
}
```

If your app genuinely has a fully public read-only API surface
served by a *separate* controller, split it into its own
`SecurityFilterChain` bean with `@Order` so the scope is
crystal-clear in source:

```java
@Bean
@Order(1)
public SecurityFilterChain publicApiSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/api/public/**")
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
        .csrf(csrf -> csrf.disable());
    return http.build();
}

@Bean
@Order(2)
public SecurityFilterChain mainSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}
```

The named filter chain documents intent. A reviewer can grep
for `publicApiSecurityFilterChain` to find every fully-public
surface.

## How to suppress

If you have one of the legitimate split-filter-chain layouts
above, suppress the broad `permitAll()` on the public chain
with a reason:

```java
http.authorizeHttpRequests(auth -> auth
    // rastray-ignore: RSTR-SPRING-001 — dedicated publicApiSecurityFilterChain, securityMatcher already scopes to /api/public/**
    .requestMatchers("/api/public/**").permitAll()
);
```

## References

- [Spring Security — Authorize HttpServletRequests](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [Spring Security — Multiple SecurityFilterChains](https://docs.spring.io/spring-security/reference/servlet/configuration/java.html#jc-httpsecurity-multiple-security-filter-chain)
- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-862 — Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
