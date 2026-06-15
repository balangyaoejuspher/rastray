# RSTR-IAC-011 — `publicly_accessible = true` on a database

## Summary

A Terraform `aws_db_instance` (or `aws_rds_cluster_instance`,
`aws_dms_replication_instance`, `aws_elasticache_*`) sets
`publicly_accessible = true`. The database receives a publicly
routable endpoint and is reachable from any source allowed by its
security group.

Combined with an over-broad security group ([RSTR-IAC-010](./RSTR-IAC-010.md))
this becomes "the database is on the internet"; even with a tight
security group, every credential spray, every leaked password, and
every cloud-credential leak gets one extra free attempt at the
database directly.

## Severity

`High`.

## Languages

Terraform (`.tf`, `.tfvars`).

## What rastray flags

```hcl
resource "aws_db_instance" "prod" {
  identifier           = "prod"
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  publicly_accessible  = true          # ← flagged
}
```

```hcl
resource "aws_rds_cluster_instance" "writer" {
  cluster_identifier   = aws_rds_cluster.prod.id
  instance_class       = "db.r6g.large"
  publicly_accessible  = true          # ← flagged
}
```

## What rastray deliberately does *not* flag

- `publicly_accessible = false` (the default).
- The presence of a public endpoint variable (`endpoint`,
  `cluster_endpoint`) — that's the resource's own DNS name, which
  resolves to a private IP unless `publicly_accessible = true`.

## How to fix it

Set `publicly_accessible = false` and connect via private
networking:

- **VPC peering** or **Transit Gateway** for cross-VPC access
  inside the same AWS account / organisation.
- **AWS PrivateLink** for SaaS-style cross-account access.
- **VPN / Direct Connect** for on-prem access.
- A **bastion** or **SSM Session Manager** for ad-hoc DBA access —
  never give the DBA team `psql` from their laptop straight to a
  public endpoint.

```hcl
resource "aws_db_instance" "prod" {
  identifier           = "prod"
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  publicly_accessible  = false
  db_subnet_group_name = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db.id]
}
```

## References

- [AWS — RDS in a VPC](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html)
- [AWS — PrivateLink for RDS](https://docs.aws.amazon.com/whitepapers/latest/build-secure-enterprise-ml-platform/amazon-rds-with-vpc-endpoints.html)
- [CWE-668](https://cwe.mitre.org/data/definitions/668.html)
