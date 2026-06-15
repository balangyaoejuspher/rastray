# RSTR-IAC-009 — S3 bucket with public ACL

## Summary

A Terraform `aws_s3_bucket` (or `aws_s3_bucket_acl`) sets
`acl = "public-read"` or `acl = "public-read-write"`. Every object
in the bucket is now readable (and, with the second form, writable)
by every IPv4 address on the public internet.

Public buckets are the single most common AWS data-leak vector
because the field is one line of HCL away from `"private"`. AWS
itself ships *four* separate guardrails to make it harder
(Block Public Access settings, IAM analyzer, security-hub
findings, bucket policy explicit-deny rules) — rastray is the same
fence at the IaC layer.

## Severity

`High`.

## Languages

Terraform (`.tf`, `.tfvars`).

## What rastray flags

```hcl
resource "aws_s3_bucket" "assets" {
  bucket = "my-org-assets"
  acl    = "public-read"             # ← flagged
}
```

```hcl
resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read-write"       # ← flagged
}
```

## What rastray deliberately does *not* flag

- `acl = "private"` (default).
- `acl = "authenticated-read"` — limited to any AWS account, which
  is a separate (smaller) blast radius and is occasionally
  intentional for cross-account delivery.
- `acl = "bucket-owner-full-control"` — required pattern for
  cross-account object writes.

## How to fix it

1. Switch the ACL to `"private"`.
2. If you need public delivery, front the bucket with CloudFront
   and an origin access identity:

   ```hcl
   resource "aws_s3_bucket" "assets" {
     bucket = "my-org-assets"
     acl    = "private"
   }

   resource "aws_cloudfront_distribution" "cdn" {
     origin {
       domain_name = aws_s3_bucket.assets.bucket_regional_domain_name
       origin_id   = "s3-assets"
       s3_origin_config {
         origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
       }
     }
     # ...
   }
   ```

3. Add `aws_s3_bucket_public_access_block` with all four flags
   set to `true` — it's a no-cost belt-and-braces:

   ```hcl
   resource "aws_s3_bucket_public_access_block" "assets" {
     bucket                  = aws_s3_bucket.assets.id
     block_public_acls       = true
     block_public_policy     = true
     ignore_public_acls      = true
     restrict_public_buckets = true
   }
   ```

## References

- [AWS — S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS — S3 ACL overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)
- [CWE-732](https://cwe.mitre.org/data/definitions/732.html)
