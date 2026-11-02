"""IAM checks: each has an insecure case (finding expected) and a fixed case (no finding)."""

from __future__ import annotations

import json

import pytest

from cloud_guard.aws.checks import iam
from cloud_guard.demo import ADMIN_POLICY, SCOPED_POLICY
from cloud_guard.models import Severity
from tests.conftest import ids

PASSWORD = "Test-Passw0rd!-not-real"


def _root_row(mfa: str, key1: str, key2: str = "false") -> dict[str, str]:
    return {"user": "<root_account>", "mfa_active": mfa, "access_key_1_active": key1, "access_key_2_active": key2}


# ----------------------------------------------------------------- root account


def test_root_fallback_to_account_summary_flags_missing_mfa(make_ctx):
    # moto's credential report has no <root_account> row, so the account-summary
    # fallback is used. moto reports AccountMFAEnabled=0 -> CG-IAM-002.
    findings = iam.check_root_account(make_ctx())
    assert ids(findings) == ["CG-IAM-002"]
    assert "account summary" in findings[0].details
    assert findings[0].severity is Severity.CRITICAL


def test_root_credential_report_insecure(make_ctx, monkeypatch):
    monkeypatch.setattr(iam, "_credential_report_rows", lambda ctx: [_root_row(mfa="false", key1="true")])
    assert ids(iam.check_root_account(make_ctx())) == ["CG-IAM-001", "CG-IAM-002"]


def test_root_credential_report_second_key_only(make_ctx, monkeypatch):
    monkeypatch.setattr(iam, "_credential_report_rows", lambda ctx: [_root_row(mfa="true", key1="false", key2="true")])
    assert ids(iam.check_root_account(make_ctx())) == ["CG-IAM-001"]


def test_root_credential_report_fixed(make_ctx, monkeypatch):
    monkeypatch.setattr(iam, "_credential_report_rows", lambda ctx: [_root_row(mfa="true", key1="false")])
    assert iam.check_root_account(make_ctx()) == []


# ----------------------------------------------------------------- user MFA


def test_console_user_without_mfa_is_flagged(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="alice")
    client.create_login_profile(UserName="alice", Password=PASSWORD)
    findings = iam.check_users_without_mfa(make_ctx())
    assert ids(findings) == ["CG-IAM-003"]
    assert findings[0].resource.endswith(":user/alice")


def test_console_user_with_mfa_passes(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="bob")
    client.create_login_profile(UserName="bob", Password=PASSWORD)
    serial = client.create_virtual_mfa_device(VirtualMFADeviceName="bob")["VirtualMFADevice"]["SerialNumber"]
    client.enable_mfa_device(UserName="bob", SerialNumber=serial, AuthenticationCode1="111111", AuthenticationCode2="222222")
    assert iam.check_users_without_mfa(make_ctx()) == []


def test_user_without_console_password_is_not_flagged_for_mfa(session, make_ctx):
    session.client("iam").create_user(UserName="svc")
    assert iam.check_users_without_mfa(make_ctx()) == []


# ----------------------------------------------------------------- access key age


def test_old_access_key_is_flagged(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="svc")
    key_id = client.create_access_key(UserName="svc")["AccessKey"]["AccessKeyId"]
    findings = iam.check_old_access_keys(make_ctx(days_ahead=100))
    assert ids(findings) == ["CG-IAM-004"]
    assert key_id not in findings[0].details  # key id is masked in reports


def test_fresh_access_key_passes(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="svc")
    client.create_access_key(UserName="svc")
    assert iam.check_old_access_keys(make_ctx(days_ahead=89)) == []


def test_old_but_inactive_key_passes(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="svc")
    key_id = client.create_access_key(UserName="svc")["AccessKey"]["AccessKeyId"]
    client.update_access_key(UserName="svc", AccessKeyId=key_id, Status="Inactive")
    assert iam.check_old_access_keys(make_ctx(days_ahead=365)) == []


# ----------------------------------------------------------------- managed policies


def test_attached_admin_policy_is_high(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="alice")
    arn = client.create_policy(PolicyName="Admin", PolicyDocument=ADMIN_POLICY)["Policy"]["Arn"]
    client.attach_user_policy(UserName="alice", PolicyArn=arn)
    findings = iam.check_admin_managed_policies(make_ctx())
    assert ids(findings) == ["CG-IAM-005"]
    assert findings[0].severity is Severity.HIGH


def test_unattached_admin_policy_is_medium(session, make_ctx):
    session.client("iam").create_policy(PolicyName="Admin", PolicyDocument=ADMIN_POLICY)
    findings = iam.check_admin_managed_policies(make_ctx())
    assert [f.severity for f in findings] == [Severity.MEDIUM]


@pytest.mark.parametrize("document", [
    SCOPED_POLICY,
    # Action * but scoped resource -> not full admin
    json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::x"}]}),
    # Deny on everything is a guard rail
    json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}),
])
def test_non_admin_policies_pass(session, make_ctx, document):
    session.client("iam").create_policy(PolicyName="Ok", PolicyDocument=document)
    assert iam.check_admin_managed_policies(make_ctx()) == []


# ----------------------------------------------------------------- inline user policies


def test_inline_admin_user_policy_is_flagged(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="alice")
    client.put_user_policy(UserName="alice", PolicyName="AdminInline", PolicyDocument=ADMIN_POLICY)
    findings = iam.check_inline_admin_user_policies(make_ctx())
    assert ids(findings) == ["CG-IAM-006"]
    assert "AdminInline" in findings[0].details


def test_scoped_inline_user_policy_passes(session, make_ctx):
    client = session.client("iam")
    client.create_user(UserName="alice")
    client.put_user_policy(UserName="alice", PolicyName="ReadOnly", PolicyDocument=SCOPED_POLICY)
    assert iam.check_inline_admin_user_policies(make_ctx()) == []
