# RSTR-NET-005 — Java HostnameVerifier accepts every hostname

## Summary

A Java program installs a custom `HostnameVerifier` whose `verify(...)`
method (or lambda body) returns `true` unconditionally. The result:
TLS still negotiates a session and validates the server certificate
chain, but the **hostname binding step** — confirming that the
certificate was actually issued for the host you intended to talk to
— is skipped. An attacker on the network path who can present *any*
valid certificate (even for a different hostname) terminates your
TLS connection and reads / modifies the traffic.

This is one of the two classic "we just want it to work, ship it"
TLS bypasses (the other is trusting all certs in a custom
`X509TrustManager`). It's particularly dangerous in mobile and
backend contexts where the application talks to a fixed
production hostname — disabling hostname verification gives every
person on a coffee-shop wifi a working MITM.

## Severity

`High`.

## Languages

Java, Kotlin (`.java`, `.kt`, `.kts`).

## What rastray flags

Lambda form:

```java
conn.setHostnameVerifier((hostname, session) -> true);              // ← flagged
```

Anonymous-inner-class form:

```java
conn.setHostnameVerifier(new HostnameVerifier() {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        return true;                                                // ← flagged
    }
});
```

## What rastray deliberately does *not* flag

A verifier that consults an allow-list:

```java
conn.setHostnameVerifier((hostname, session) -> ALLOWED_HOSTS.contains(hostname));
```

Or one that delegates to the JDK default after a guard:

```java
HostnameVerifier defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
conn.setHostnameVerifier((hostname, session) ->
    INTERNAL_HOSTS.contains(hostname) || defaultVerifier.verify(hostname, session));
```

## How to fix it

The simplest answer: **delete the custom verifier**. The JDK default
verifier checks the certificate's `subjectAlternativeName` against
the hostname you connected to, which is the correct behaviour for
99% of cases. Only override if you have a specific reason
(self-signed cert pinned by hash, internal CA, on-device
certificate-pinning library).

If overriding is genuinely needed:

```java
conn.setHostnameVerifier((hostname, session) -> {
    if (!ALLOWED_HOSTS.contains(hostname)) {
        return false;
    }
    return HttpsURLConnection.getDefaultHostnameVerifier()
        .verify(hostname, session);
});
```

For HTTP clients that wrap `URLConnection` (OkHttp, Retrofit), use
the framework's hostname-verifier hook rather than reaching into the
underlying connection.

## How to suppress

If the verifier is intentionally permissive in a test-only context
(e.g. integration tests against a self-signed local server),
suppress per-line:

```java
// rastray-ignore: RSTR-NET-005 — local integration test only, never compiled into release builds
conn.setHostnameVerifier((hostname, session) -> true);
```

Or scope the rule to non-test files in `.rastray.toml`.

## References

- [OWASP — Testing for Weak Transport Layer Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)
- [SEI CERT Java MSC03-J](https://wiki.sei.cmu.edu/confluence/display/java/MSC03-J.+Never+hard+code+sensitive+information)
- [CWE-295 — Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-297 — Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)
