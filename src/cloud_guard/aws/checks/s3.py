"""S3 checks: public buckets, Block Public Access, default encryption.

How "public" works in S3 (the part interviewers like to probe):
  * A bucket can be opened up by an ACL grant to the AllUsers /
    AuthenticatedUsers groups, OR by a bucket policy with Principal "*".
  * S3 Block Public Access (BPA) is an override with four switches, set at the
    account level and/or the bucket level. If IgnorePublicAcls is on, public
    ACLs are ignored; if RestrictPublicBuckets is on, public policies are
    neutralised. So we compute the *effective* BPA before calling something
    public - otherwise we'd raise false alarms.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from cloud_guard import cis
from cloud_guard.aws.context import AwsContext
from cloud_guard.aws.errors import ACCESS_DENIED_CODES, error_code
from cloud_guard.models import Finding, Severity
from cloud_guard.policy import load_policy, public_statements

BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "everyone (AllUsers)",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "any AWS account (AuthenticatedUsers)",
}
NO_BPA = {key: False for key in BPA_KEYS}


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _account_bpa(ctx: AwsContext) -> dict[str, bool]:
    """Account-wide Block Public Access settings (all False if never configured)."""
    try:
        resp = ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)
        return {k: bool(resp["PublicAccessBlockConfiguration"].get(k)) for k in BPA_KEYS}
    except ClientError as exc:
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return dict(NO_BPA)
        raise


def _bucket_bpa(ctx: AwsContext, bucket: str) -> dict[str, bool]:
    """Bucket-level Block Public Access settings (all False if never configured)."""
    try:
        resp = ctx.client("s3").get_public_access_block(Bucket=bucket)
        return {k: bool(resp["PublicAccessBlockConfiguration"].get(k)) for k in BPA_KEYS}
    except ClientError as exc:
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return dict(NO_BPA)
        raise


def _public_acl_grants(ctx: AwsContext, bucket: str) -> list[str]:
    """Return descriptions like 'everyone (AllUsers): READ' for public ACL grants."""
    grants = ctx.client("s3").get_bucket_acl(Bucket=bucket)["Grants"]
    public = []
    for grant in grants:
        uri = grant.get("Grantee", {}).get("URI")
        if uri in PUBLIC_GROUP_URIS:
            public.append(f"{PUBLIC_GROUP_URIS[uri]}: {grant.get('Permission')}")
    return public


def _bucket_policy(ctx: AwsContext, bucket: str) -> dict[str, Any] | None:
    """Return the bucket policy as a dict, or None if the bucket has no policy."""
    try:
        return load_policy(ctx.client("s3").get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if error_code(exc) == "NoSuchBucketPolicy":
            return None
        raise


def _has_default_encryption(ctx: AwsContext, bucket: str) -> bool:
    try:
        rules = ctx.client("s3").get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
        return len(rules) > 0
    except ClientError as exc:
        if error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
            return False
        raise


def _scan_bucket(ctx: AwsContext, bucket: str, account_bpa: dict[str, bool]) -> list[Finding]:
    """Run every S3 rule against one bucket."""
    arn = _bucket_arn(bucket)
    bucket_bpa = _bucket_bpa(ctx, bucket)
    # A protection is effective if it's on at EITHER the account or bucket level.
    effective = {k: account_bpa[k] or bucket_bpa[k] for k in BPA_KEYS}
    findings: list[Finding] = []

    public_grants = _public_acl_grants(ctx, bucket)
    if public_grants and not effective["IgnorePublicAcls"]:
        findings.append(Finding(
            id="CG-S3-001",
            title="S3 bucket is public via ACL",
            severity=Severity.CRITICAL,
            resource=arn,
            cis=cis.S3_PUBLIC,
            remediation="Remove the AllUsers/AuthenticatedUsers grants, set Object Ownership to 'BucketOwnerEnforced' (disables ACLs), and enable Block Public Access.",
            details="; ".join(public_grants),
        ))

    policy = _bucket_policy(ctx, bucket)
    if policy and public_statements(policy) and not effective["RestrictPublicBuckets"]:
        findings.append(Finding(
            id="CG-S3-002",
            title="S3 bucket is public via bucket policy",
            severity=Severity.CRITICAL,
            resource=arn,
            cis=cis.S3_PUBLIC,
            remediation="Remove 'Principal: *' Allow statements or restrict them with a Condition (e.g. aws:SourceVpce). Serve public content through CloudFront with Origin Access Control instead.",
            details=f"{len(public_statements(policy))} statement(s) allow Principal '*' with no Condition",
        ))

    if not all(effective.values()):
        missing = [k for k, on in effective.items() if not on]
        findings.append(Finding(
            id="CG-S3-003",
            title="S3 Block Public Access is not fully enabled",
            severity=Severity.MEDIUM,
            resource=arn,
            cis=cis.S3_BLOCK_PUBLIC_ACCESS,
            remediation="Enable all four Block Public Access settings at the account level (and on the bucket) unless the bucket is intentionally public.",
            details="off: " + ", ".join(missing),
        ))

    if not _has_default_encryption(ctx, bucket):
        findings.append(Finding(
            id="CG-S3-004",
            title="S3 bucket has no default encryption configured",
            severity=Severity.LOW,
            resource=arn,
            cis=cis.S3_ENCRYPTION,
            remediation="Configure default encryption (SSE-KMS with a customer-managed key if you need key-level access control and audit).",
        ))
    return findings


def check_s3_buckets(ctx: AwsContext) -> list[Finding]:
    """CG-S3-001..004 for every bucket in the account.

    A permission error on ONE bucket (e.g. a bucket policy that denies our
    scanner) is recorded as a skip and we carry on with the other buckets.
    """
    account_bpa = _account_bpa(ctx)
    findings: list[Finding] = []
    for bucket in ctx.client("s3").list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            findings.extend(_scan_bucket(ctx, name, account_bpa))
        except ClientError as exc:
            if error_code(exc) in ACCESS_DENIED_CODES:
                ctx.skip("s3_buckets", f"bucket {name}: permission denied ({error_code(exc)})")
            else:
                raise
    return findings

