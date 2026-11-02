"""Command-line interface.

    cloud-guard scan-aws [--profile P] [--region R]
    cloud-guard scan-terraform <dir>
    cloud-guard demo

Exit codes (so a CI pipeline can act on them):
    0 = scan completed, no findings at or above --fail-on
    1 = scan completed, findings at or above --fail-on
    2 = the scan could not run (bad arguments, no credentials, missing dir)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from botocore.exceptions import ProfileNotFound

from cloud_guard import __version__
from cloud_guard.aws.scanner import CredentialsMissingError
from cloud_guard.models import ScanResult, Severity
from cloud_guard.reporting import RENDERERS
from cloud_guard.reporting.console import render_summary, render_table

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
FAIL_ON_CHOICES = ["none"] + [s.name.lower() for s in Severity]


def _add_output_options(parser: argparse.ArgumentParser, default_fail_on: str) -> None:
    parser.add_argument("--format", choices=sorted(RENDERERS), default="table",
                        help="output format (default: table)")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="write the report to FILE instead of stdout (a table summary is still printed)")
    parser.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default=default_fail_on,
                        help=f"exit with code 1 if any finding is at least this severe (default: {default_fail_on})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-guard",
        description="Read-only AWS posture scanner and Terraform checker mapped to CIS AWS Foundations v3.0.0.",
    )
    parser.add_argument("--version", action="version", version=f"cloud-guard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    aws = sub.add_parser("scan-aws", help="scan a live AWS account (read-only API calls)")
    aws.add_argument("--profile", help="AWS named profile to use (default: normal credential chain)")
    aws.add_argument("--region", help="region to scan for regional checks (default: profile region or us-east-1)")
    _add_output_options(aws, default_fail_on="high")

    tf = sub.add_parser("scan-terraform", help="statically scan Terraform .tf files")
    tf.add_argument("directory", help="directory containing .tf files (searched recursively)")
    _add_output_options(tf, default_fail_on="high")

    demo = sub.add_parser("demo", help="scan a mocked (moto) AWS account full of deliberate misconfigurations")
    _add_output_options(demo, default_fail_on="none")
    return parser


def _run_scan(args: argparse.Namespace) -> ScanResult:
    """Dispatch to the right scanner. Imports are local so that, e.g.,
    `scan-terraform` never imports moto."""
    if args.command == "scan-terraform":
        from cloud_guard.terraform.scanner import scan_terraform
        return scan_terraform(args.directory)
    if args.command == "demo":
        from cloud_guard.demo import DEMO_CLOCK_SHIFT_DAYS, run_demo
        print(f"[demo] Using moto: an in-memory fake AWS account. No real AWS calls are made.\n"
              f"[demo] The scan clock is shifted +{DEMO_CLOCK_SHIFT_DAYS} days so access-key-age checks fire.\n",
              file=sys.stderr)
        return run_demo()
    from cloud_guard.aws.context import AwsContext, build_session
    from cloud_guard.aws.scanner import run_aws_scan
    session, region = build_session(args.profile, args.region)
    return run_aws_scan(AwsContext(session=session, region=region))


def _emit(result: ScanResult, fmt: str, output: str | None) -> None:
    """Print or save the report in the chosen format."""
    report = RENDERERS[fmt](result)
    if output:
        Path(output).write_text(report, encoding="utf-8")
        print(render_table(result))
        print(f"\nReport written to {output}")
    else:
        print(report)


def exit_code_for(result: ScanResult, fail_on: str) -> int:
    """Map scan results and the --fail-on threshold to a process exit code."""
    if fail_on == "none":
        return EXIT_OK
    return EXIT_FINDINGS if result.has_findings_at_or_above(Severity.from_str(fail_on)) else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = _run_scan(args)
    except (FileNotFoundError, CredentialsMissingError, ProfileNotFound) as exc:
        # "Could not scan" is a different outcome from "scanned and found problems".
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    _emit(result, args.format, args.output)
    code = exit_code_for(result, args.fail_on)
    if code == EXIT_FINDINGS:
        print(f"\nFAIL: findings at or above '{args.fail_on}' ({render_summary(result)})", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
