# RSTR-DES-005 — Ruby `Marshal.load`

## Summary

`Marshal.load` (and the alias `Marshal.restore`) deserializes Ruby
objects from a binary blob, and the deserializer will invoke
attacker-controlled object initializers (`_load`, `marshal_load`,
`initialize_copy`). Famous Rails gadget chains turn a single
`Marshal.load` of attacker bytes into full RCE.

## Severity

`Critical`.

## Languages

Ruby.

## What rastray flags

```ruby
data = Marshal.load(request.body.read)             # ← flagged
data = Marshal.restore(File.binread('cache.bin'))  # ← flagged
```

## What rastray deliberately does *not* flag

- `JSON.parse(...)`, `Psych.safe_load(...)`, `MessagePack.unpack(...)`.

## How to fix it

Use JSON (or MessagePack for binary):

```ruby
data = JSON.parse(request.body.read, symbolize_names: true)
```

If you must use Marshal for a closed internal channel (Rails
`Marshal`-backed cache), sign the blob with HMAC-SHA-256 and verify
before unmarshalling. Even then, the surface is large enough that
swapping to JSON or `Psych.safe_load` is usually cheaper than
maintaining the signing harness.

## References

- [Rails security guide — `Marshal`](https://guides.rubyonrails.org/security.html#unsafe-query-generation)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [HackerOne: classic Rails Marshal exploit](https://hackerone.com/reports/473596)
