"""CloudTrail checks: is there an audit log, does it cover all regions, is it tamper-evident?

Why it matters: CloudTrail is the "CCTV" of an AWS account. Without it you
cannot answer "who did what, when" after an incident. Attackers often operate
in regions you don't use, which is why the trail must be multi-region. Log file
validation adds SHA-256 digest files so you can prove logs weren't edited.
"""

from __future__ import annotations

from typing import Any

from cloud_guard import cis
from cloud_guard.aws.context import AwsContext
from cloud_guard.models import Finding, Severity


def _list_trails(ctx: AwsContext) -> list[dict[str, Any]]:
    """All trails visible from the scan region.

    includeShadowTrails=True also returns multi-region trails whose "home" is
    another region - those still protect this region, so they must count.
    """
    return ctx.client("cloudtrail").describe_trails(includeShadowTrails=True).get("trailList", [])


def _is_logging(ctx: AwsContext, trail: dict[str, Any]) -> bool:
    """A trail can exist but be stopped; GetTrailStatus tells us which."""
    home = trail.get("HomeRegion") or ctx.region
    status = ctx.client("cloudtrail", region=home).get_trail_status(Name=trail["TrailARN"])
    return bool(status.get("IsLogging"))


def check_cloudtrail(ctx: AwsContext) -> list[Finding]:
    """CG-CT-001..004: trail exists, is logging, is multi-region, has log validation."""
    trails = _list_trails(ctx)
    if not trails:
        return [Finding(
            id="CG-CT-001",
            title="No CloudTrail trail is configured",
            severity=Severity.HIGH,
            resource=ctx.account_arn,
            cis=cis.CLOUDTRAIL_MULTI_REGION,
            remediation="Create a multi-region trail (ideally an organization trail) that logs management events to a dedicated, locked-down S3 bucket.",
            details=f"checked from region {ctx.region}",
        )]

    findings: list[Finding] = []
    has_active_multi_region = False
    for trail in trails:
        arn = trail["TrailARN"]
        logging = _is_logging(ctx, trail)
        if not logging:
            findings.append(Finding(
                id="CG-CT-004",
                title="CloudTrail trail exists but logging is stopped",
                severity=Severity.HIGH,
                resource=arn,
                cis=f"approx. {cis.CLOUDTRAIL_MULTI_REGION}",
                remediation="Start logging (StartLogging) and alert on StopLogging events - stopping a trail is a classic attacker move.",
            ))
        if logging and trail.get("IsMultiRegionTrail"):
            has_active_multi_region = True
        if not trail.get("LogFileValidationEnabled"):
            findings.append(Finding(
                id="CG-CT-003",
                title="CloudTrail log file validation is disabled",
                severity=Severity.MEDIUM,
                resource=arn,
                cis=cis.CLOUDTRAIL_LOG_VALIDATION,
                remediation="Enable log file validation so tampering with or deleting log files can be detected.",
            ))

    if not has_active_multi_region:
        findings.append(Finding(
            id="CG-CT-002",
            title="No active multi-region CloudTrail trail",
            severity=Severity.MEDIUM,
            resource=ctx.account_arn,
            cis=cis.CLOUDTRAIL_MULTI_REGION,
            remediation="Set IsMultiRegionTrail=true on a trail (or create one) so activity in every region is recorded.",
            details=f"{len(trails)} trail(s) found, none both multi-region and logging",
        ))
    return findings
