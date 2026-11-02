"""EC2 checks: security groups open to the internet on admin ports, EBS default encryption.

Security groups are stateful virtual firewalls. Port 22 (SSH) and 3389 (RDP)
open to 0.0.0.0/0 are constantly brute-forced by internet-wide scanners within
minutes of a server going up. Admin access should go through SSM Session
Manager, a VPN or a bastion with a narrow source CIDR.
"""

from __future__ import annotations

from typing import Any, Iterator

from cloud_guard import cis
from cloud_guard.aws.context import AwsContext
from cloud_guard.models import Finding, Severity
from cloud_guard.netrules import ADMIN_PORTS, OPEN_IPV4, OPEN_IPV6, covers_port


def _iter_security_groups(ctx: AwsContext) -> Iterator[dict[str, Any]]:
    paginator = ctx.client("ec2").get_paginator("describe_security_groups")
    for page in paginator.paginate():
        yield from page["SecurityGroups"]


def rule_covers_port(permission: dict[str, Any], port: int) -> bool:
    """True if an EC2 ingress permission (API shape) allows traffic to `port`.

    IpProtocol "-1" means all protocols and ports, so FromPort/ToPort may be
    absent; covers_port handles that case.
    """
    return covers_port(
        permission.get("IpProtocol", ""), permission.get("FromPort"), permission.get("ToPort"), port
    )


def _open_sources(permission: dict[str, Any]) -> list[str]:
    """Which "whole internet" CIDRs (IPv4 and/or IPv6) a permission allows."""
    sources = []
    if any(r.get("CidrIp") == OPEN_IPV4 for r in permission.get("IpRanges", [])):
        sources.append(OPEN_IPV4)
    if any(r.get("CidrIpv6") == OPEN_IPV6 for r in permission.get("Ipv6Ranges", [])):
        sources.append(OPEN_IPV6)
    return sources


def check_security_groups(ctx: AwsContext) -> list[Finding]:
    """CG-EC2-001: ingress from 0.0.0.0/0 or ::/0 to port 22 or 3389.

    One finding per (security group, port, source) so the report shows exactly
    what to close. Duplicate rules are de-duplicated with a set.
    """
    findings: list[Finding] = []
    for group in _iter_security_groups(ctx):
        arn = f"arn:aws:ec2:{ctx.region}:{group.get('OwnerId', ctx.account_id)}:security-group/{group['GroupId']}"
        seen: set[tuple[int, str]] = set()
        for permission in group.get("IpPermissions", []):
            for source in _open_sources(permission):
                for port, label in ADMIN_PORTS.items():
                    if (port, source) in seen or not rule_covers_port(permission, port):
                        continue
                    seen.add((port, source))
                    findings.append(Finding(
                        id="CG-EC2-001",
                        title=f"Security group allows {label} (port {port}) from the internet",
                        severity=Severity.HIGH,
                        resource=arn,
                        cis=cis.SG_ADMIN_PORTS if source == OPEN_IPV4 else cis.SG_ADMIN_PORTS_IPV6,
                        remediation="Remove the rule. Use SSM Session Manager (no inbound ports) or restrict the source to a known VPN/office CIDR.",
                        details=f"group '{group.get('GroupName')}' allows {source} -> port {port} (protocol {permission.get('IpProtocol')})",
                    ))
    return findings


def check_ebs_default_encryption(ctx: AwsContext) -> list[Finding]:
    """CG-EC2-002: EBS encryption-by-default is a per-region account setting.

    With it on, every new volume and snapshot copy is encrypted automatically,
    so no engineer can forget. It's regional, so a full audit would run this in
    every region you use (run cloud-guard once per --region).
    """
    enabled = ctx.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    if enabled:
        return []
    return [Finding(
        id="CG-EC2-002",
        title="EBS encryption by default is disabled",
        severity=Severity.MEDIUM,
        resource=ctx.account_arn,
        cis=cis.EBS_DEFAULT_ENCRYPTION,
        remediation="Enable 'Always encrypt new EBS volumes' (EnableEbsEncryptionByDefault) in every region you use.",
        details=f"region {ctx.region}",
    )]
