# RSTR-IAC-008 — PodSpec shares a host namespace

## Summary

A Kubernetes PodSpec sets one of `hostNetwork: true`,
`hostPID: true`, or `hostIPC: true`. Each of these collapses one of
the isolation boundaries between the container and the host:

| flag | what the pod now sees |
|------|------------------------|
| `hostNetwork` | the node's network stack: every interface, every listening socket, the node's DNS config |
| `hostPID` | every process on the node (and can signal them) |
| `hostIPC` | the node's System V IPC and POSIX shared-memory segments |

Combined with a privileged container or a writable `hostPath`
mount, any of these is a one-hop pivot from "compromise the pod"
to "compromise the node".

## Severity

`High`.

## Languages

Kubernetes YAML manifests (any workload-bearing kind).

## What rastray flags

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: net-tool
spec:
  hostNetwork: true                  # ← flagged
  containers:
    - name: tool
      image: net:1.0
```

```yaml
spec:
  hostPID: true                      # ← flagged
```

```yaml
spec:
  hostIPC: true                      # ← flagged
```

## What rastray deliberately does *not* flag

- `hostNetwork: false` / `hostPID: false` / `hostIPC: false`
  (the default).
- `hostname: <something>` — different field entirely, no isolation
  impact.
- `hostAliases` — appends to `/etc/hosts`, doesn't expand the
  blast radius.

## How to fix it

Remove the host-namespace flag. Use a Service for incoming traffic,
a SidecarContainer for log shipping, and a CSI driver for any
shared-state needs.

If the workload genuinely requires host access (CNI plugin,
node-local DNS, kube-proxy), document the threat model in the
manifest comments, pin the workload to a dedicated node pool, and
enforce `restricted` PSA in every other namespace.

## References

- [Kubernetes — Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark — host* namespaces](https://www.cisecurity.org/benchmark/kubernetes)
- [CWE-653](https://cwe.mitre.org/data/definitions/653.html)
