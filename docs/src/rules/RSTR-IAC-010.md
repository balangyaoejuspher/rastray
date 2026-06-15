# RSTR-IAC-010 — Security-group rule with `0.0.0.0/0`

## Summary

A Terraform security-group or network ACL rule sets
`cidr_blocks = ["0.0.0.0/0"]`. The associated port is reachable from
every IPv4 address on the public internet. When the rule covers an
admin port (22 SSH, 3389 RDP, 5432 PostgreSQL, 3306 MySQL, 6379
Redis, 27017 Mongo, 9200 Elasticsearch, …), the blast radius is the
entire service.

The pattern is convenient enough that examples in tutorials still
ship with it. Convenience does not change the threat model.

## Severity

`Critical`.

## Languages

Terraform (`.tf`, `.tfvars`).

## What rastray flags

```hcl
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]        # ← flagged
  }
}
```

```hcl
resource "aws_security_group_rule" "db" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]          # ← flagged
}
```

## What rastray deliberately does *not* flag

- `cidr_blocks = ["10.0.0.0/8"]` and similar RFC1918 ranges.
- `cidr_blocks = ["<office-cidr>"]` — narrow public range, still
  intentional.
- `cidr_blocks = ["::/0"]` (IPv6 equivalent — separate concern,
  handled by a future rule once IPv6 deployments are more common
  in real codebases).

## How to fix it

1. For admin ports (22, 3389), use SSM Session Manager / EC2
   Instance Connect or a bastion. Never expose admin ports to the
   internet.
2. For application ports, front the service with an ALB / API
   Gateway and tighten the security group to allow only the load
   balancer's security group:

   ```hcl
   resource "aws_security_group_rule" "web" {
     type                     = "ingress"
     from_port                = 443
     to_port                  = 443
     protocol                 = "tcp"
     source_security_group_id = aws_security_group.alb.id
   }
   ```

3. If a public endpoint is genuinely required, document the threat
   model in a comment next to the resource, and rely on the
   application's authentication layer to gate access.

## References

- [AWS — Security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- [AWS — Connect to an EC2 instance with SSM Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
- [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
