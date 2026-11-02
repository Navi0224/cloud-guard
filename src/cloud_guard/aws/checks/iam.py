"""IAM checks: root account hygiene, MFA, key age, and over-broad policies.

Every call here is read-only (Get*/List*/Generate+GetCredentialReport).
Note: GenerateCredentialReport only *builds* a report; it changes no settings.
"""

from __future__ import annotations

import csv
import io
import time
from datetime import timedelta
from typing import Any, Iterator

from botocore.exceptions import ClientError

from cloud_guard import cis
from cloud_guard.aws.context import AwsContext
from cloud_guard.aws.errors import error_code
from cloud_guard.models import Finding, Severity
from cloud_guard.policy import has_admin_statement, load_policy

MAX_KEY_AGE_DAYS = 90
ROOT_ROW_NAME = "<root_account>"


# --------------------------------------------------------------------------- helpers


def _iter_users(ctx: AwsContext) -> Iterator[dict[str, Any]]:
    """Yield every IAM user, following pagination (accounts can have thousands)."""
    paginator = ctx.client("iam").get_paginator("list_users")
    for page in paginator.paginate():
        yield from page["Users"]


def _has_console_password(ctx: AwsContext, user_name: str) -> bool:
    """A user has console access if a login profile exists."""
    try:
        ctx.client("iam").get_login_profile(UserName=user_name)
        return True
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            return False
        raise


def _mask_key(key_id: str) -> str:
    """Show only the start/end of an access key id in reports (defence in depth)."""
    return f"{key_id[:4]}...{key_id[-4:]}" if len(key_id) > 8 else "****"


def _credential_report_rows(ctx: AwsContext, attempts: int = 10) -> list[dict[str, str]]:
    """Generate (if needed) and download the IAM credential report as dict rows.

    The report is built asynchronously by AWS, so we poll a few times.
    """
    iam = ctx.client("iam")
    delay = 0.2
    for _ in range(attempts):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(delay)
        delay = min(delay * 2, 2.0)  # simple exponential back-off
    content = iam.get_credential_report()["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return list(csv.DictReader(io.StringIO(text)))


# --------------------------------------------------------------------------- checks


def check_root_account(ctx: AwsContext) -> list[Finding]:
    """CG-IAM-001 / CG-IAM-002: root user must have MFA and no access keys.

    Why it matters: the root user cannot be restricted by IAM policies. Root
    access keys are permanent god-mode credentials; leaked once, the account is
    lost. MFA on root is the single most important account control.

    Data source: the credential report's <root_account> row. Some backends
    (including moto) leave that row out, so we fall back to GetAccountSummary,
    which exposes the same two facts as counters.
    """
    rows = _credential_report_rows(ctx)
    root = next((r for r in rows if r.get("user") == ROOT_ROW_NAME), None)
    if root is not None:
        has_keys = root.get("access_key_1_active") == "true" or root.get("access_key_2_active") == "true"
        mfa_on = root.get("mfa_active") == "true"
        source = "credential report"
    else:
        summary = ctx.client("iam").get_account_summary()["SummaryMap"]
        has_keys = summary.get("AccountAccessKeysPresent", 0) > 0
        mfa_on = summary.get("AccountMFAEnabled", 0) == 1
        source = "account summary (credential report had no root row)"

    findings: list[Finding] = []
    if has_keys:
        findings.append(Finding(
            id="CG-IAM-001",
            title="Root account has active access keys",
            severity=Severity.CRITICAL,
            resource=ctx.account_arn,
            cis=cis.ROOT_ACCESS_KEYS,
            remediation="Delete the root user's access keys. Use IAM roles or IAM Identity Center for programmatic access.",
            details=f"source: {source}",
        ))
    if not mfa_on:
        findings.append(Finding(
            id="CG-IAM-002",
            title="Root account does not have MFA enabled",
            severity=Severity.CRITICAL,
            resource=ctx.account_arn,
            cis=cis.ROOT_MFA,
            remediation="Sign in as root and enable MFA (ideally a hardware key). Lock the root credentials away.",
            details=f"source: {source}",
        ))
    return findings


def check_users_without_mfa(ctx: AwsContext) -> list[Finding]:
    """CG-IAM-003: every user who can log in to the console must have MFA.

    We only flag users with a console password (matches CIS 1.10). A user with
    only access keys cannot use console MFA in the same way; key hygiene is
    covered by CG-IAM-004 instead.
    """
    iam = ctx.client("iam")
    findings: list[Finding] = []
    for user in _iter_users(ctx):
        name = user["UserName"]
        if not _has_console_password(ctx, name):
            continue
        if iam.list_mfa_devices(UserName=name)["MFADevices"]:
            continue
        findings.append(Finding(
            id="CG-IAM-003",
            title="IAM user has console access but no MFA",
            severity=Severity.HIGH,
            resource=user["Arn"],
            cis=cis.USER_MFA,
            remediation="Enable an MFA device for this user, and enforce MFA with an IAM policy condition (aws:MultiFactorAuthPresent).",
        ))
    return findings


def check_old_access_keys(ctx: AwsContext) -> list[Finding]:
    """CG-IAM-004: active access keys older than 90 days.

    Long-lived keys are the most common way AWS accounts get breached (committed
    to GitHub, left on laptops). Rotation limits how long a leaked key is useful.
    """
    iam = ctx.client("iam")
    cutoff = ctx.now - timedelta(days=MAX_KEY_AGE_DAYS)
    findings: list[Finding] = []
    for user in _iter_users(ctx):
        for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
            if key["Status"] != "Active" or key["CreateDate"] >= cutoff:
                continue
            age = (ctx.now - key["CreateDate"]).days
            findings.append(Finding(
                id="CG-IAM-004",
                title=f"Access key older than {MAX_KEY_AGE_DAYS} days",
                severity=Severity.MEDIUM,
                resource=user["Arn"],
                cis=cis.KEY_ROTATION,
                remediation="Create a new key, switch applications to it, then deactivate and delete the old one. Prefer IAM roles over keys.",
                details=f"key {_mask_key(key['AccessKeyId'])} is {age} days old",
            ))
    return findings


def check_admin_managed_policies(ctx: AwsContext) -> list[Finding]:
    """CG-IAM-005: customer-managed policies granting Action "*" on Resource "*".

    We only look at *customer* managed policies (Scope=Local). AWS's own
    AdministratorAccess is expected to exist; what matters is who you attach it
    to. Attached admin policies are HIGH; unattached ones are MEDIUM (a loaded
    gun lying around).
    """
    iam = ctx.client("iam")
    findings: list[Finding] = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for pol in page["Policies"]:
            version = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
            document = load_policy(version["PolicyVersion"]["Document"])
            if not has_admin_statement(document):
                continue
            attached = pol.get("AttachmentCount", 0) > 0
            findings.append(Finding(
                id="CG-IAM-005",
                title="Customer-managed policy allows full admin (Action * on Resource *)",
                severity=Severity.HIGH if attached else Severity.MEDIUM,
                resource=pol["Arn"],
                cis=cis.NO_FULL_ADMIN_POLICIES,
                remediation="Replace wildcards with the specific actions and resource ARNs needed (least privilege). Use IAM Access Analyzer to generate a policy from real usage.",
                details=f"attached to {pol.get('AttachmentCount', 0)} principal(s)",
            ))
    return findings


def check_inline_admin_user_policies(ctx: AwsContext) -> list[Finding]:
    """CG-IAM-006: inline policies on users that grant full admin.

    Two problems at once: (1) admin rights, and (2) attached directly to a user
    instead of via a group/role, so it's invisible in normal policy reviews.
    """
    iam = ctx.client("iam")
    findings: list[Finding] = []
    for user in _iter_users(ctx):
        name = user["UserName"]
        for policy_name in iam.list_user_policies(UserName=name)["PolicyNames"]:
            doc = iam.get_user_policy(UserName=name, PolicyName=policy_name)["PolicyDocument"]
            if has_admin_statement(load_policy(doc)):
                findings.append(Finding(
                    id="CG-IAM-006",
                    title="Inline admin policy attached directly to IAM user",
                    severity=Severity.HIGH,
                    resource=user["Arn"],
                    cis=f"{cis.PERMISSIONS_VIA_GROUPS}, {cis.NO_FULL_ADMIN_POLICIES}",
                    remediation="Delete the inline policy. Grant scoped permissions through a group or role instead.",
                    details=f"inline policy '{policy_name}'",
                ))
    return findings
