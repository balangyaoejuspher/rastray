# RSTR-IAC-007 — `privileged: true` container

## Summary

A Kubernetes PodSpec sets `securityContext.privileged: true` (or a
container-level `securityContext.privileged: true`). A privileged
container runs with the same effective capabilities as the host
kernel: it can mount any filesystem, load kernel modules, talk to
all devices under `/dev`, and reach into other containers' cgroups.

`privileged: true` is the kubernetes-equivalent of `--privileged`
on a Docker run, and the same caveat applies: it is rarely the
right answer, and when it is (host-level monitoring agent, CNI
plugin, low-level GPU bring-up), the workload should be carved off
into a dedicated node pool with its own RBAC.

## Severity

`High`.

## Languages

Kubernetes YAML manifests (`Pod`, `Deployment`, `StatefulSet`,
`DaemonSet`, `Job`, `CronJob`, `ReplicaSet`,
`ReplicationController`).

## What rastray flags

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: app:1.0
      securityContext:
        privileged: true              # ← flagged
```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: agent:1.0
          securityContext:
            privileged: true          # ← flagged
```

## What rastray deliberately does *not* flag

- `privileged: false` (the default; explicit-false is a good signal
  in policy-as-code).
- `allowPrivilegeEscalation: true` — separate concern, handled by
  policy admission controllers.

## How to fix it

Drop the `privileged: true` and request only the specific Linux
capabilities you actually need:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]        # only what you need
  allowPrivilegeEscalation: false
  runAsNonRoot: true
```

If the workload genuinely needs host-level access (CSI driver,
node-exporter, low-level networking), keep it on a dedicated node
pool with PSA `restricted` enforcement on every other namespace,
and review the pod spec at every release.

## References

- [Kubernetes — Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes — Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CWE-250](https://cwe.mitre.org/data/definitions/250.html)
