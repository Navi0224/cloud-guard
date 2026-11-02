"""Registry of all AWS checks.

Adding a new check = write a function `(ctx) -> list[Finding]` and add one line
to ALL_CHECKS. The runner does the rest (error handling, counting, reporting).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cloud_guard.aws.checks import cloudtrail, ec2, iam, s3
from cloud_guard.aws.context import AwsContext
from cloud_guard.models import Finding

CheckFunc = Callable[[AwsContext], list[Finding]]


@dataclass(frozen=True)
class AwsCheck:
    """A registered check: a name (used in skip messages), the ids it can emit, and the function."""

    name: str
    finding_ids: tuple[str, ...]
    func: CheckFunc


ALL_CHECKS: tuple[AwsCheck, ...] = (
    AwsCheck("iam_root_account", ("CG-IAM-001", "CG-IAM-002"), iam.check_root_account),
    AwsCheck("iam_user_mfa", ("CG-IAM-003",), iam.check_users_without_mfa),
    AwsCheck("iam_access_key_age", ("CG-IAM-004",), iam.check_old_access_keys),
    AwsCheck("iam_admin_managed_policies", ("CG-IAM-005",), iam.check_admin_managed_policies),
    AwsCheck("iam_inline_admin_user_policies", ("CG-IAM-006",), iam.check_inline_admin_user_policies),
    AwsCheck("s3_buckets", ("CG-S3-001", "CG-S3-002", "CG-S3-003", "CG-S3-004"), s3.check_s3_buckets),
    AwsCheck("cloudtrail", ("CG-CT-001", "CG-CT-002", "CG-CT-003", "CG-CT-004"), cloudtrail.check_cloudtrail),
    AwsCheck("ec2_security_groups", ("CG-EC2-001",), ec2.check_security_groups),
    AwsCheck("ec2_ebs_default_encryption", ("CG-EC2-002",), ec2.check_ebs_default_encryption),
)
