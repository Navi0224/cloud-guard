"""The runner: full-account scan, graceful skips, and missing credentials."""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from cloud_guard.aws.checks import ALL_CHECKS, AwsCheck
from cloud_guard.aws.scanner import CredentialsMissingError, run_aws_scan
from cloud_guard.demo import run_demo, seed_insecure_account

EXPECTED_DEMO_IDS = {
    "CG-IAM-002", "CG-IAM-003", "CG-IAM-004", "CG-IAM-005", "CG-IAM-006",
    "CG-S3-001", "CG-S3-002", "CG-S3-003", "CG-S3-004",
    "CG-CT-002", "CG-CT-003",
    "CG-EC2-001", "CG-EC2-002",
}


def test_full_scan_of_seeded_account(session, make_ctx):
    seed_insecure_account(session)
    result = run_aws_scan(make_ctx(days_ahead=120))
    assert result.checks_run == len(ALL_CHECKS)
    assert result.skipped == []  # every check is supported by moto
    assert {f.id for f in result.findings} == EXPECTED_DEMO_IDS
    # The secure resources in the seed must NOT appear.
    resources = " ".join(f.resource for f in result.findings)
    assert "cg-demo-secure" not in resources and "user/bob" not in resources


def test_demo_entrypoint_matches_seed():
    result = run_demo()
    assert {f.id for f in result.findings} == EXPECTED_DEMO_IDS
    assert "moto mock" in result.target


def _raising_check(exc: Exception) -> AwsCheck:
    def boom(ctx):
        raise exc
    return AwsCheck("boom", ("X",), boom)


@pytest.mark.parametrize("exc,expected_reason", [
    (ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "ListUsers"), "permission denied"),
    (ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "x"}}, "DescribeSecurityGroups"), "permission denied"),
    (NotImplementedError("moto does not support this"), "not implemented"),
    (ClientError({"Error": {"Code": "OptInRequired", "Message": "x"}}, "DescribeTrails"), "not supported"),
])
def test_check_errors_become_skips(make_ctx, exc, expected_reason):
    ok = AwsCheck("ok", ("Y",), lambda ctx: [])
    result = run_aws_scan(make_ctx(), checks=(_raising_check(exc), ok))
    assert result.checks_run == 2
    assert [s.check_id for s in result.skipped] == ["boom"]
    assert expected_reason in result.skipped[0].reason


def test_missing_credentials_raise_friendly_error(make_ctx, monkeypatch):
    ctx = make_ctx()

    class NoCredsClient:
        def get_caller_identity(self):
            raise NoCredentialsError()

    monkeypatch.setattr(ctx, "client", lambda service, region=None: NoCredsClient())
    with pytest.raises(CredentialsMissingError, match="cloud-guard demo"):
        run_aws_scan(ctx)
