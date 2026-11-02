"""`cloud-guard demo`: scan a fake AWS account that lives entirely in memory.

moto intercepts every boto3 call inside `mock_aws()`, so this needs no AWS
account, no internet access and no credentials - and it cannot touch a real
account even if one is configured, because we use hard-coded dummy keys and
moto answers every request locally.

The seeding functions are also used by the test-suite, so "what the demo
shows" and "what the tests prove" are the same misconfigurations.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import boto3
from moto import mock_aws

from cloud_guard.aws.context import AwsContext
from cloud_guard.aws.scanner import run_aws_scan
from cloud_guard.models import ScanResult

DEMO_REGION = "us-east-1"
# Access keys created by moto are brand new. To show the ">90 days" check
# firing, the demo scans "as if" it were this many days in the future.
DEMO_CLOCK_SHIFT_DAYS = 120

ADMIN_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
SCOPED_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::cg-demo-secure/*"}],
})
ALL_BPA_ON = {
    "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
}


def fake_session(region: str = DEMO_REGION) -> boto3.session.Session:
    """A boto3 session with dummy credentials (only ever used under moto)."""
    return boto3.session.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name=region
    )


def public_read_policy(bucket: str) -> str:
    """A bucket policy that lets anyone on the internet read every object."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    })


def make_secure_bucket(s3, name: str) -> None:
    """Bucket with Block Public Access fully on and default KMS encryption."""
    s3.create_bucket(Bucket=name)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_BPA_ON)
    s3.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
    )


def seed_iam(session: boto3.session.Session) -> None:
    """alice = risky admin without MFA; bob = MFA-protected; svc-ci = key-only service user."""
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Demo-Passw0rd!-not-real")
    iam.create_access_key(UserName="alice")
    iam.put_user_policy(UserName="alice", PolicyName="AdminInline", PolicyDocument=ADMIN_POLICY)
    admin = iam.create_policy(PolicyName="PowerfulAdmin", PolicyDocument=ADMIN_POLICY)["Policy"]["Arn"]
    iam.attach_user_policy(UserName="alice", PolicyArn=admin)
    iam.create_policy(PolicyName="ReadSecureBucket", PolicyDocument=SCOPED_POLICY)

    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Demo-Passw0rd!-not-real")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(UserName="bob", SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321")

    iam.create_user(UserName="svc-ci")
    iam.create_access_key(UserName="svc-ci")


def seed_s3(session: boto3.session.Session) -> None:
    """Two public buckets (ACL and policy) and one locked-down bucket."""
    s3 = session.client("s3")
    s3.create_bucket(Bucket="cg-demo-public-acl")
    s3.put_bucket_acl(Bucket="cg-demo-public-acl", ACL="public-read")
    s3.create_bucket(Bucket="cg-demo-public-policy")
    s3.put_bucket_policy(Bucket="cg-demo-public-policy", Policy=public_read_policy("cg-demo-public-policy"))
    make_secure_bucket(s3, "cg-demo-secure")


def seed_cloudtrail(session: boto3.session.Session) -> None:
    """A trail that is logging, but single-region and without log file validation."""
    make_secure_bucket(session.client("s3"), "cg-demo-trail-logs")
    ct = session.client("cloudtrail")
    ct.create_trail(Name="cg-demo-trail", S3BucketName="cg-demo-trail-logs",
                    IsMultiRegionTrail=False, EnableLogFileValidation=False)
    ct.start_logging(Name="cg-demo-trail")


def seed_ec2(session: boto3.session.Session) -> None:
    """One security group with SSH+RDP open to the world, one sensible web SG.
    EBS encryption-by-default is left at its default (off)."""
    ec2 = session.client("ec2")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    bad = ec2.create_security_group(GroupName="cg-demo-open-admin", Description="demo: too open", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=bad, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ])
    web = ec2.create_security_group(GroupName="cg-demo-web", Description="demo: https only", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ])


def seed_insecure_account(session: boto3.session.Session) -> None:
    """Create every deliberate misconfiguration used by the demo."""
    seed_iam(session)
    seed_s3(session)
    seed_cloudtrail(session)
    seed_ec2(session)


def run_demo(clock_shift_days: int = DEMO_CLOCK_SHIFT_DAYS) -> ScanResult:
    """Spin up a mocked account, seed it, scan it, and return the result."""
    with mock_aws():
        session = fake_session()
        seed_insecure_account(session)
        now = datetime.now(timezone.utc) + timedelta(days=clock_shift_days)
        ctx = AwsContext(session=session, region=DEMO_REGION, now=now)
        result = run_aws_scan(ctx)
    result.target = f"{result.target} [moto mock - demo data]"
    return result
