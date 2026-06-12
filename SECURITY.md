# Security Policy

`rastray` is a security-focused tool, so we take vulnerabilities in `rastray` itself seriously.

## Supported versions

Until the project reaches `1.0.0`, only the latest release on the `main` branch is supported. Older `0.x` releases will not receive backports.

| Version  | Supported          |
| -------- | ------------------ |
| `main`   | ✅                 |
| `< main` | ❌                 |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately via **[GitHub Security Advisories](https://github.com/balangyaoejuspher/rastray/security/advisories/new)**. This keeps the report encrypted, lets us coordinate a fix without disclosing the issue, and gives you a clear channel to track progress.

When reporting, please include:

1. A description of the vulnerability and its impact.
2. Steps to reproduce, ideally with a minimal proof-of-concept.
3. The version (commit hash or release tag) you tested against.
4. Your name and a way we can credit you, if you'd like to be acknowledged.

## Disclosure process

- We will acknowledge receipt within **3 business days**.
- We aim to triage and confirm within **7 business days**.
- We target a fix and coordinated disclosure within **90 days** of the initial report. Critical issues may be patched faster.
- Once a fix is released, the advisory and credit will be published.

## Scope

In scope:

- The `rastray` binary and its source modules.
- Any analyzer false-negative that would cause `rastray` to silently miss a class of real security issue it claims to detect.
- Dependency-chain vulnerabilities that affect `rastray` at runtime.

Out of scope:

- Findings produced *by* `rastray` against third-party code — report those to the affected project.
- Theoretical issues without a practical attack path.
- Vulnerabilities requiring a privileged local attacker (e.g., write access to `Cargo.toml`).
