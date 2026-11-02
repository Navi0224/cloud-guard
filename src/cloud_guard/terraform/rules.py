"""Terraform static-analysis rules ("shift-left" versions of the AWS checks).

Each rule takes ALL parsed blocks (not one at a time) because some questions
span resources: "is this bucket encrypted by a *separate*
aws_s3_bucket_server_side_encryption_configuration resource?" or "is there a
CloudTrail anywhere in this configuration?".
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from cloud_guard import cis
from cloud_guard.models import Finding, Severity
from cloud_guard.netrules import ADMIN_PORTS, OPEN_IPV4, OPEN_IPV6, covers_port
from cloud_guard.policy import has_admin_statement, is_admin_statement
from cloud_guard.terraform.parser import TerraformBlock, as_list

Rule = Callable[[list[TerraformBlock]], list[Finding]]

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
INLINE_POLICY_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}


# --------------------------------------------------------------------------- helpers


def _of_type(blocks: list[TerraformBlock], rtype: str, kind: str = "resource") -> list[TerraformBlock]:
    return [b for b in blocks if b.type == rtype and b.kind == kind]


def _is_true(value: Any) -> bool:
    """HCL booleans may arrive as True or as the string 'true'."""
    return value is True or str(value).strip().lower() == "true"


def _referenced_bucket_names(value: Any) -> set[str]:
    """Find `aws_s3_bucket.<name>` references inside an expression like "${aws_s3_bucket.logs.id}"."""
    return set(re.findall(r"aws_s3_bucket\.([A-Za-z0-9_-]+)", str(value)))


def _hcl_object_to_json(text: str) -> str:
    """Best-effort conversion of an HCL object literal (from jsonencode) to JSON.

    python-hcl2 gives us jsonencode({Version = "2012-10-17", Statement = [...]})
    as text. Turning `Key =` into `"Key":` makes it valid JSON in the common
    case of literal values. If it contains references (aws_s3_bucket.x.arn) the
    result won't parse and the caller falls back to a regex.
    """
    text = re.sub(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*=', r'"\1":', text)
    return re.sub(r"(?<![\"\w])([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", r'"\1":', text)


_WILDCARD_ACTION = re.compile(r'"?Action"?\s*[=:]\s*(\[[^\]]*"\*"[^\]]*\]|"\*")')
_WILDCARD_RESOURCE = re.compile(r'"?Resource"?\s*[=:]\s*(\[[^\]]*"\*"[^\]]*\]|"\*")')


def policy_text_is_admin(policy: Any) -> bool | None:
    """Decide whether a Terraform `policy` attribute grants full admin.

    Returns True/False, or None when the value is a reference we can't see into
    (e.g. data.aws_iam_policy_document.x.json - that data source is checked by
    its own rule).
    """
    text = str(policy).strip()
    if text.startswith("${jsonencode(") and text.endswith(")}"):
        inner = text[len("${jsonencode("):-2]
        try:
            return has_admin_statement(json.loads(_hcl_object_to_json(inner)))
        except ValueError:
            # Fallback heuristic: both a wildcard Action and a wildcard Resource appear.
            return bool(_WILDCARD_ACTION.search(inner) and _WILDCARD_RESOURCE.search(inner))
    if text.startswith("{"):
        try:
            return has_admin_statement(json.loads(text))
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- rules


def rule_public_s3_acl(blocks: list[TerraformBlock]) -> list[Finding]:
    """TF-S3-001: bucket ACL set to a public canned ACL.

    Covers both the old inline style (aws_s3_bucket.acl, AWS provider v3) and
    the separate aws_s3_bucket_acl resource (provider v4+).
    """
    findings = []
    for block in _of_type(blocks, "aws_s3_bucket") + _of_type(blocks, "aws_s3_bucket_acl"):
        acl = str(block.body.get("acl", "")).strip()
        if acl in PUBLIC_ACLS:
            findings.append(Finding(
                id="TF-S3-001",
                title="S3 bucket uses a public ACL",
                severity=Severity.CRITICAL,
                resource=block.location,
                cis=cis.S3_PUBLIC,
                remediation='Use acl = "private" (or drop ACLs: aws_s3_bucket_ownership_controls with BucketOwnerEnforced) and add aws_s3_bucket_public_access_block.',
                details=f'acl = "{acl}"',
            ))
    return findings


def rule_s3_missing_encryption(blocks: list[TerraformBlock]) -> list[Finding]:
    """TF-S3-002: bucket has no server-side encryption configuration in code.

    Note: since January 2023 AWS applies SSE-S3 to new objects automatically,
    so this is a policy-as-code rule ("encryption must be explicit, ideally
    with KMS") rather than "the data is stored in plaintext".
    """
    encrypted: set[str] = set()
    for cfg in _of_type(blocks, "aws_s3_bucket_server_side_encryption_configuration"):
        encrypted |= _referenced_bucket_names(cfg.body.get("bucket"))
    findings = []
    for bucket in _of_type(blocks, "aws_s3_bucket"):
        inline = bucket.body.get("server_side_encryption_configuration")
        if inline or bucket.name in encrypted:
            continue
        findings.append(Finding(
            id="TF-S3-002",
            title="S3 bucket has no server-side encryption configuration",
            severity=Severity.LOW,
            resource=bucket.location,
            cis=cis.S3_ENCRYPTION,
            remediation="Add an aws_s3_bucket_server_side_encryption_configuration resource (sse_algorithm = \"aws:kms\" with a customer-managed key).",
        ))
    return findings


def rule_ebs_unencrypted(blocks: list[TerraformBlock]) -> list[Finding]:
    """TF-EBS-001: EBS volume without `encrypted = true`."""
    findings = []
    for vol in _of_type(blocks, "aws_ebs_volume"):
        if _is_true(vol.body.get("encrypted")):
            continue
        findings.append(Finding(
            id="TF-EBS-001",
            title="EBS volume is not encrypted",
            severity=Severity.MEDIUM,
            resource=vol.location,
            cis=f"approx. {cis.EBS_DEFAULT_ENCRYPTION}",
            remediation="Set encrypted = true (and kms_key_id), and enable aws_ebs_encryption_by_default for the account.",
        ))
    return findings


def _ingress_rules(blocks: list[TerraformBlock]) -> list[tuple[TerraformBlock, dict[str, Any]]]:
    """Normalise the three ways Terraform can express an ingress rule into
    (block, {"protocol", "from_port", "to_port", "cidrs"}) tuples."""
    rules: list[tuple[TerraformBlock, dict[str, Any]]] = []
    for sg in _of_type(blocks, "aws_security_group"):
        for ing in as_list(sg.body.get("ingress")):
            rules.append((sg, {
                "protocol": ing.get("protocol"), "from_port": ing.get("from_port"), "to_port": ing.get("to_port"),
                "cidrs": as_list(ing.get("cidr_blocks")) + as_list(ing.get("ipv6_cidr_blocks")),
            }))
    for rule in _of_type(blocks, "aws_security_group_rule"):
        if str(rule.body.get("type")) != "ingress":
            continue
        rules.append((rule, {
            "protocol": rule.body.get("protocol"), "from_port": rule.body.get("from_port"),
            "to_port": rule.body.get("to_port"),
            "cidrs": as_list(rule.body.get("cidr_blocks")) + as_list(rule.body.get("ipv6_cidr_blocks")),
        }))
    for rule in _of_type(blocks, "aws_vpc_security_group_ingress_rule"):
        rules.append((rule, {
            "protocol": rule.body.get("ip_protocol"), "from_port": rule.body.get("from_port"),
            "to_port": rule.body.get("to_port"),
            "cidrs": as_list(rule.body.get("cidr_ipv4")) + as_list(rule.body.get("cidr_ipv6")),
        }))
    return rules


def rule_sg_open_admin_ports(blocks: list[TerraformBlock]) -> list[Finding]:
    """TF-SG-001: ingress from 0.0.0.0/0 or ::/0 to SSH (22) or RDP (3389)."""
    findings = []
    for block, rule in _ingress_rules(blocks):
        open_cidrs = [c for c in rule["cidrs"] if str(c) in (OPEN_IPV4, OPEN_IPV6)]
        for cidr in open_cidrs:
            for port, label in ADMIN_PORTS.items():
                if not covers_port(rule["protocol"], rule["from_port"], rule["to_port"], port):
                    continue
                findings.append(Finding(
                    id="TF-SG-001",
                    title=f"Security group allows {label} (port {port}) from the internet",
                    severity=Severity.HIGH,
                    resource=block.location,
                    cis=cis.SG_ADMIN_PORTS if cidr == OPEN_IPV4 else cis.SG_ADMIN_PORTS_IPV6,
                    remediation="Restrict the source CIDR to a VPN/office range, or remove the rule and use SSM Session Manager.",
                    details=f"{cidr} -> port {port} (protocol {rule['protocol']})",
                ))
    return findings


def rule_iam_wildcard_policy(blocks: list[TerraformBlock]) -> list[Finding]:
    """TF-IAM-001: IAM policy allowing Action "*" on Resource "*".

    Checks inline JSON/jsonencode policies on aws_iam_*policy resources and
    statements in data "aws_iam_policy_document" blocks.
    """
    findings = []

    def _finding(block: TerraformBlock) -> Finding:
        return Finding(
            id="TF-IAM-001",
            title="IAM policy allows full admin (Action * on Resource *)",
            severity=Severity.HIGH,
            resource=block.location,
            cis=cis.NO_FULL_ADMIN_POLICIES,
            remediation="List only the actions and resource ARNs the workload needs. Validate with IAM Access Analyzer policy validation.",
        )

    for block in blocks:
        if block.kind == "resource" and block.type in INLINE_POLICY_TYPES:
            if policy_text_is_admin(block.body.get("policy")):
                findings.append(_finding(block))
    for doc in _of_type(blocks, "aws_iam_policy_document", kind="data"):
        for stmt in as_list(doc.body.get("statement")):
            as_iam = {
                "Effect": str(stmt.get("effect", "Allow")),  # Terraform's default effect is Allow
                "Action": as_list(stmt.get("actions")),
                "Resource": as_list(stmt.get("resources")),
            }
            if is_admin_statement(as_iam):
                findings.append(_finding(doc))
                break
    return findings


def rule_cloudtrail(blocks: list[TerraformBlock]) -> list[Finding]:
    """TF-CT-001..003: a CloudTrail exists, is multi-region, has log validation.

    TF-CT-001 is a judgement call: the trail may legitimately live in another
    repository (e.g. an organization trail in a central "security" account),
    which is why it is MEDIUM, not HIGH.
    """
    trails = _of_type(blocks, "aws_cloudtrail")
    if not trails:
        return [Finding(
            id="TF-CT-001",
            title="No aws_cloudtrail resource in this Terraform configuration",
            severity=Severity.MEDIUM,
            resource="(scanned directory)",
            cis=cis.CLOUDTRAIL_MULTI_REGION,
            remediation="Define a multi-region aws_cloudtrail here, or confirm an organization trail covers this account.",
        )]
    findings = []
    for trail in trails:
        if not _is_true(trail.body.get("is_multi_region_trail")):
            findings.append(Finding(
                id="TF-CT-002",
                title="CloudTrail is not multi-region",
                severity=Severity.MEDIUM,
                resource=trail.location,
                cis=cis.CLOUDTRAIL_MULTI_REGION,
                remediation="Set is_multi_region_trail = true.",
            ))
        if not _is_true(trail.body.get("enable_log_file_validation")):
            findings.append(Finding(
                id="TF-CT-003",
                title="CloudTrail log file validation is disabled",
                severity=Severity.MEDIUM,
                resource=trail.location,
                cis=cis.CLOUDTRAIL_LOG_VALIDATION,
                remediation="Set enable_log_file_validation = true.",
            ))
    return findings


ALL_RULES: tuple[Rule, ...] = (
    rule_public_s3_acl,
    rule_s3_missing_encryption,
    rule_ebs_unencrypted,
    rule_sg_open_admin_ports,
    rule_iam_wildcard_policy,
    rule_cloudtrail,
)
