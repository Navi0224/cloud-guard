"""Runs every registered AWS check and collects the results.

Design choice: each check runs inside its own try/except. If the scanning role
is missing, say, cloudtrail:DescribeTrails, we record "skipped: permission
denied" and still run the IAM, S3 and EC2 checks. A partial report you can see
the gaps in is far more useful than a crash.
"""

from __future__ import annotations

from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from cloud_guard.aws.checks import ALL_CHECKS, AwsCheck
from cloud_guard.aws.context import AwsContext
from cloud_guard.aws.errors import describe_skip_reason
from cloud_guard.models import ScanResult


class CredentialsMissingError(RuntimeError):
    """Raised when credentials are missing or rejected - nothing can run."""


def run_aws_scan(ctx: AwsContext, checks: tuple[AwsCheck, ...] = ALL_CHECKS) -> ScanResult:
    """Run `checks` against the account in `ctx` and return a ScanResult."""
    try:
        account = ctx.account_id  # fail fast with a clear message if creds are missing
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsMissingError(
            "No AWS credentials found. Configure a profile (aws configure / aws sso login) "
            "or try `cloud-guard demo`, which needs no AWS account."
        ) from exc
    except ClientError as exc:
        raise CredentialsMissingError(
            f"Could not identify the AWS account via sts:GetCallerIdentity: {describe_skip_reason(exc)}"
        ) from exc

    result = ScanResult(target=f"aws account {account} (region {ctx.region})")
    for check in checks:
        result.checks_run += 1
        try:
            result.findings.extend(check.func(ctx))
        except (NoCredentialsError, PartialCredentialsError):
            raise
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see module docstring
            ctx.skip(check.name, describe_skip_reason(exc))
    result.skipped.extend(ctx.skipped)
    return result
