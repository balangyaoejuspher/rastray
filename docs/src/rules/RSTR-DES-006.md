# RSTR-DES-006 — Java `ObjectInputStream.readObject`

## Summary

Native Java deserialization (`ObjectInputStream.readObject`) walks the
attacker-controlled byte stream and instantiates whatever classes it
names, invoking their `readObject` / `readResolve` hooks. The
notorious **CVE-2015-7501** (Apache Commons Collections) chained a
small number of common gadgets into JVM-wide RCE; the pattern has been
re-used against countless Java apps since.

## Severity

`Critical`.

## Languages

Java, Kotlin.

## What rastray flags

```java
ObjectInputStream ois = new ObjectInputStream(input);   // ← flagged
Object o = ois.readObject();                            // ← flagged
```

```kotlin
val ois = ObjectInputStream(input)
val o = ois.readObject()                                // ← flagged
```

## What rastray deliberately does *not* flag

- JSON / XML / MessagePack / protobuf deserializers.
- Reads of objects you serialized yourself from a closed channel
  *and* validated with a serialization-filter (`ObjectInputFilter`)
  that rejects everything outside an allow-list.

## How to fix it

Switch the wire format. JSON via Jackson or Gson, protobuf, Avro —
any data-only format eliminates the gadget surface.

If you cannot change the format, install a JEP-290 serialization
filter that rejects every class outside an explicit allow-list:

```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.dto.*;java.lang.*;!*"
);
ObjectInputFilter.Config.setSerialFilter(filter);
```

A correctly-scoped filter is a hard lower bound — the JVM rejects the
byte stream before any gadget can run.

## References

- [JEP 290 — Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
- [Frohoff & Lawrence: Marshalling Pickles](https://frohoff.github.io/appseccali-marshalling-pickles/) (the original talk)
- [CVE-2015-7501](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
