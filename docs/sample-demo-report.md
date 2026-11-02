# cloud-guard report

- **Target:** aws account 123456789012 (region us-east-1) [moto mock - demo data]
- **Generated:** 2026-11-02 14:54 UTC by cloud-guard 0.1.0
- **Mapped to:** CIS AWS Foundations Benchmark v3.0.0 (see README for mapping caveats)
- **Checks run:** 9

## Summary by severity

| Severity | Count |
|---|---|
| CRITICAL | 3 |
| HIGH | 5 |
| MEDIUM | 7 |
| LOW | 2 |
| INFO | 0 |

## Findings

| Severity | ID | Title | Resource | CIS | Remediation |
|---|---|---|---|---|---|
| CRITICAL | CG-IAM-002 | Root account does not have MFA enabled (source: account summary (credential report had no root row)) | `arn:aws:iam::123456789012:root` | CIS 1.5 | Sign in as root and enable MFA (ideally a hardware key). Lock the root credentials away. |
| CRITICAL | CG-S3-001 | S3 bucket is public via ACL (everyone (AllUsers): READ) | `arn:aws:s3:::cg-demo-public-acl` | approx. CIS 2.1.4 | Remove the AllUsers/AuthenticatedUsers grants, set Object Ownership to 'BucketOwnerEnforced' (disables ACLs), and enable Block Public Access. |
| CRITICAL | CG-S3-002 | S3 bucket is public via bucket policy (1 statement(s) allow Principal '*' with no Condition) | `arn:aws:s3:::cg-demo-public-policy` | approx. CIS 2.1.4 | Remove 'Principal: *' Allow statements or restrict them with a Condition (e.g. aws:SourceVpce). Serve public content through CloudFront with Origin Access Control instead. |
| HIGH | CG-EC2-001 | Security group allows SSH (port 22) from the internet (group 'cg-demo-open-admin' allows 0.0.0.0/0 -> port 22 (protocol tcp)) | `arn:aws:ec2:us-east-1:123456789012:security-group/sg-e28ecec6bdce5fa31` | CIS 5.2 | Remove the rule. Use SSM Session Manager (no inbound ports) or restrict the source to a known VPN/office CIDR. |
| HIGH | CG-EC2-001 | Security group allows RDP (port 3389) from the internet (group 'cg-demo-open-admin' allows 0.0.0.0/0 -> port 3389 (protocol tcp)) | `arn:aws:ec2:us-east-1:123456789012:security-group/sg-e28ecec6bdce5fa31` | CIS 5.2 | Remove the rule. Use SSM Session Manager (no inbound ports) or restrict the source to a known VPN/office CIDR. |
| HIGH | CG-IAM-003 | IAM user has console access but no MFA | `arn:aws:iam::123456789012:user/alice` | CIS 1.10 | Enable an MFA device for this user, and enforce MFA with an IAM policy condition (aws:MultiFactorAuthPresent). |
| HIGH | CG-IAM-005 | Customer-managed policy allows full admin (Action * on Resource *) (attached to 1 principal(s)) | `arn:aws:iam::123456789012:policy/PowerfulAdmin` | CIS 1.16 | Replace wildcards with the specific actions and resource ARNs needed (least privilege). Use IAM Access Analyzer to generate a policy from real usage. |
| HIGH | CG-IAM-006 | Inline admin policy attached directly to IAM user (inline policy 'AdminInline') | `arn:aws:iam::123456789012:user/alice` | CIS 1.15, CIS 1.16 | Delete the inline policy. Grant scoped permissions through a group or role instead. |
| MEDIUM | CG-CT-002 | No active multi-region CloudTrail trail (1 trail(s) found, none both multi-region and logging) | `arn:aws:iam::123456789012:root` | CIS 3.1 | Set IsMultiRegionTrail=true on a trail (or create one) so activity in every region is recorded. |
| MEDIUM | CG-CT-003 | CloudTrail log file validation is disabled | `arn:aws:cloudtrail:us-east-1:123456789012:trail/cg-demo-trail` | CIS 3.2 | Enable log file validation so tampering with or deleting log files can be detected. |
| MEDIUM | CG-EC2-002 | EBS encryption by default is disabled (region us-east-1) | `arn:aws:iam::123456789012:root` | CIS 2.2.1 | Enable 'Always encrypt new EBS volumes' (EnableEbsEncryptionByDefault) in every region you use. |
| MEDIUM | CG-IAM-004 | Access key older than 90 days (key AKIA...G6E6 is 120 days old) | `arn:aws:iam::123456789012:user/alice` | CIS 1.14 | Create a new key, switch applications to it, then deactivate and delete the old one. Prefer IAM roles over keys. |
| MEDIUM | CG-IAM-004 | Access key older than 90 days (key AKIA...DX2P is 120 days old) | `arn:aws:iam::123456789012:user/svc-ci` | CIS 1.14 | Create a new key, switch applications to it, then deactivate and delete the old one. Prefer IAM roles over keys. |
| MEDIUM | CG-S3-003 | S3 Block Public Access is not fully enabled (off: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) | `arn:aws:s3:::cg-demo-public-acl` | CIS 2.1.4 | Enable all four Block Public Access settings at the account level (and on the bucket) unless the bucket is intentionally public. |
| MEDIUM | CG-S3-003 | S3 Block Public Access is not fully enabled (off: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) | `arn:aws:s3:::cg-demo-public-policy` | CIS 2.1.4 | Enable all four Block Public Access settings at the account level (and on the bucket) unless the bucket is intentionally public. |
| LOW | CG-S3-004 | S3 bucket has no default encryption configured | `arn:aws:s3:::cg-demo-public-acl` | No v3.0.0 control (was 2.1.1 in v1.5.0; AWS now encrypts new buckets by default) | Configure default encryption (SSE-KMS with a customer-managed key if you need key-level access control and audit). |
| LOW | CG-S3-004 | S3 bucket has no default encryption configured | `arn:aws:s3:::cg-demo-public-policy` | No v3.0.0 control (was 2.1.1 in v1.5.0; AWS now encrypts new buckets by default) | Configure default encryption (SSE-KMS with a customer-managed key if you need key-level access control and audit). |
