"""CloudTrail and EC2 (security group, EBS) checks."""

from __future__ import annotations

import pytest

from cloud_guard import cis
from cloud_guard.aws.checks import cloudtrail, ec2
from cloud_guard.demo import make_secure_bucket
from cloud_guard.netrules import covers_port
from tests.conftest import ids

LOG_BUCKET = "cg-test-trail-logs"


def _trail(session, name="main-trail", multi=True, validation=True, logging=True):
    """Create a trail (and its log bucket on first use) with the given settings."""
    s3 = session.client("s3")
    if LOG_BUCKET not in {b["Name"] for b in s3.list_buckets().get("Buckets", [])}:
        make_secure_bucket(s3, LOG_BUCKET)
    ct = session.client("cloudtrail")
    ct.create_trail(Name=name, S3BucketName=LOG_BUCKET, IsMultiRegionTrail=multi, EnableLogFileValidation=validation)
    if logging:
        ct.start_logging(Name=name)


# ----------------------------------------------------------------- CloudTrail


def test_no_trail_is_flagged(make_ctx):
    assert ids(cloudtrail.check_cloudtrail(make_ctx())) == ["CG-CT-001"]


def test_good_trail_passes(session, make_ctx):
    _trail(session)
    assert cloudtrail.check_cloudtrail(make_ctx()) == []


def test_single_region_trail_without_validation(session, make_ctx):
    _trail(session, multi=False, validation=False)
    assert ids(cloudtrail.check_cloudtrail(make_ctx())) == ["CG-CT-002", "CG-CT-003"]


def test_stopped_trail_is_flagged(session, make_ctx):
    _trail(session, logging=False)
    # Not logging -> CT-004, and a stopped multi-region trail doesn't satisfy CT-002.
    assert ids(cloudtrail.check_cloudtrail(make_ctx())) == ["CG-CT-002", "CG-CT-004"]


def test_one_good_trail_satisfies_multi_region(session, make_ctx):
    _trail(session)
    _trail(session, name="extra", multi=False, validation=True)
    assert cloudtrail.check_cloudtrail(make_ctx()) == []


# ----------------------------------------------------------------- port logic (pure function)


@pytest.mark.parametrize("protocol,from_port,to_port,port,expected", [
    ("tcp", 22, 22, 22, True),
    ("tcp", 0, 65535, 3389, True),
    ("6", 20, 25, 22, True),
    ("udp", 3389, 3389, 3389, True),
    ("-1", None, None, 22, True),
    ("all", 0, 0, 3389, True),
    ("tcp", 443, 443, 22, False),
    ("icmp", -1, -1, 22, False),
    ("tcp", "${var.port}", "${var.port}", 22, False),  # unresolved Terraform variable
])
def test_covers_port(protocol, from_port, to_port, port, expected):
    assert covers_port(protocol, from_port, to_port, port) is expected


# ----------------------------------------------------------------- security groups


def _sg(session, name, permissions):
    client = session.client("ec2")
    group_id = client.create_security_group(GroupName=name, Description=name)["GroupId"]
    client.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    return group_id


def _sg_findings(make_ctx, group_id):
    return [f for f in ec2.check_security_groups(make_ctx()) if f.resource.endswith(group_id)]


def test_ssh_open_to_world_is_flagged(session, make_ctx):
    gid = _sg(session, "ssh", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    findings = _sg_findings(make_ctx, gid)
    assert ids(findings) == ["CG-EC2-001"]
    assert findings[0].cis == cis.SG_ADMIN_PORTS


def test_rdp_open_to_world_ipv6_is_flagged(session, make_ctx):
    gid = _sg(session, "rdp6", [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    findings = _sg_findings(make_ctx, gid)
    assert ids(findings) == ["CG-EC2-001"]
    assert findings[0].cis == cis.SG_ADMIN_PORTS_IPV6


def test_all_traffic_rule_flags_both_ports(session, make_ctx):
    gid = _sg(session, "all", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert ids(_sg_findings(make_ctx, gid)) == ["CG-EC2-001", "CG-EC2-001"]


def test_ssh_from_private_range_passes(session, make_ctx):
    gid = _sg(session, "vpn", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    assert _sg_findings(make_ctx, gid) == []


def test_https_open_to_world_passes(session, make_ctx):
    gid = _sg(session, "web", [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert _sg_findings(make_ctx, gid) == []


def test_default_security_groups_pass(make_ctx):
    # moto's default VPC security group only allows traffic from itself.
    assert ec2.check_security_groups(make_ctx()) == []


# ----------------------------------------------------------------- EBS default encryption


def test_ebs_default_encryption_off_is_flagged(make_ctx):
    assert ids(ec2.check_ebs_default_encryption(make_ctx())) == ["CG-EC2-002"]


def test_ebs_default_encryption_on_passes(session, make_ctx):
    session.client("ec2").enable_ebs_encryption_by_default()
    assert ec2.check_ebs_default_encryption(make_ctx()) == []
