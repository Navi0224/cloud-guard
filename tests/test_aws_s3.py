"""S3 checks: public ACL, public policy, Block Public Access, default encryption."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from cloud_guard.aws.checks import s3 as s3_checks
from cloud_guard.demo import ALL_BPA_ON, make_secure_bucket, public_read_policy
from tests.conftest import ids

BUCKET = "cg-test-bucket"
ACCOUNT = "123456789012"  # moto's default account id


def _scan(make_ctx, bucket: str = BUCKET):
    """Run the S3 check and return only findings for `bucket`."""
    return [f for f in s3_checks.check_s3_buckets(make_ctx()) if f.resource == f"arn:aws:s3:::{bucket}"]


# ----------------------------------------------------------------- baseline


def test_secure_bucket_has_no_findings(session, make_ctx):
    make_secure_bucket(session.client("s3"), BUCKET)
    assert _scan(make_ctx) == []


def test_new_bucket_in_moto_lacks_bpa_and_encryption(session, make_ctx):
    # Real AWS turns BPA + SSE-S3 on for new buckets; moto doesn't, which lets us test the rules.
    session.client("s3").create_bucket(Bucket=BUCKET)
    assert ids(_scan(make_ctx)) == ["CG-S3-003", "CG-S3-004"]


# ----------------------------------------------------------------- public ACL


def test_public_acl_is_flagged(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_acl(Bucket=BUCKET, ACL="public-read")
    findings = [f for f in _scan(make_ctx) if f.id == "CG-S3-001"]
    assert len(findings) == 1
    assert "AllUsers" in findings[0].details


def test_authenticated_users_acl_is_flagged(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_acl(Bucket=BUCKET, ACL="authenticated-read")
    assert "CG-S3-001" in ids(_scan(make_ctx))


def test_private_acl_passes(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_acl(Bucket=BUCKET, ACL="private")
    assert "CG-S3-001" not in ids(_scan(make_ctx))


def test_public_acl_neutralised_by_bucket_bpa_passes(session, make_ctx):
    # IgnorePublicAcls makes the public grant ineffective, so it isn't a real exposure.
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_acl(Bucket=BUCKET, ACL="public-read")
    client.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=ALL_BPA_ON)
    assert ids(_scan(make_ctx)) == ["CG-S3-004"]


# ----------------------------------------------------------------- public policy


def test_public_bucket_policy_is_flagged(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_policy(Bucket=BUCKET, Policy=public_read_policy(BUCKET))
    assert "CG-S3-002" in ids(_scan(make_ctx))


def test_principal_aws_star_policy_is_flagged(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    policy = json.loads(public_read_policy(BUCKET))
    policy["Statement"][0]["Principal"] = {"AWS": "*"}
    client.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))
    assert "CG-S3-002" in ids(_scan(make_ctx))


def test_policy_restricted_by_condition_passes(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    policy = json.loads(public_read_policy(BUCKET))
    policy["Statement"][0]["Condition"] = {"StringEquals": {"aws:SourceVpce": "vpce-1234"}}
    client.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))
    assert "CG-S3-002" not in ids(_scan(make_ctx))


def test_specific_principal_policy_passes(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    policy = json.loads(public_read_policy(BUCKET))
    policy["Statement"][0]["Principal"] = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}
    client.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))
    assert "CG-S3-002" not in ids(_scan(make_ctx))


# ----------------------------------------------------------------- Block Public Access


def test_partial_bpa_is_flagged(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    partial = dict(ALL_BPA_ON, RestrictPublicBuckets=False)
    client.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=partial)
    findings = [f for f in _scan(make_ctx) if f.id == "CG-S3-003"]
    assert findings and "RestrictPublicBuckets" in findings[0].details


def test_account_level_bpa_covers_all_buckets(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_policy(Bucket=BUCKET, Policy=public_read_policy(BUCKET))
    session.client("s3control").put_public_access_block(
        AccountId=ACCOUNT, PublicAccessBlockConfiguration=ALL_BPA_ON
    )
    # Account BPA neutralises the public policy and satisfies the BPA check.
    assert ids(_scan(make_ctx)) == ["CG-S3-004"]


# ----------------------------------------------------------------- encryption


def test_missing_default_encryption_is_flagged(session, make_ctx):
    session.client("s3").create_bucket(Bucket=BUCKET)
    assert "CG-S3-004" in ids(_scan(make_ctx))


def test_sse_s3_default_encryption_passes(session, make_ctx):
    client = session.client("s3")
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_encryption(
        Bucket=BUCKET,
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    )
    assert "CG-S3-004" not in ids(_scan(make_ctx))


# ----------------------------------------------------------------- error handling


def test_access_denied_on_one_bucket_is_skipped_not_fatal(session, make_ctx, monkeypatch):
    client = session.client("s3")
    client.create_bucket(Bucket="cg-locked-bucket")
    client.create_bucket(Bucket=BUCKET)
    real = s3_checks._bucket_bpa

    def deny_locked(ctx, bucket):
        if bucket == "cg-locked-bucket":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetPublicAccessBlock")
        return real(ctx, bucket)

    monkeypatch.setattr(s3_checks, "_bucket_bpa", deny_locked)
    ctx = make_ctx()
    findings = s3_checks.check_s3_buckets(ctx)
    assert {f.resource for f in findings} == {f"arn:aws:s3:::{BUCKET}"}
    assert len(ctx.skipped) == 1 and "cg-locked-bucket" in ctx.skipped[0].reason
