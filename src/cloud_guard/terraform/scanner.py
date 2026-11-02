"""Entry point for Terraform scanning: parse a directory, run every rule."""

from __future__ import annotations

from pathlib import Path

from cloud_guard.models import ScanResult, SkippedCheck
from cloud_guard.terraform.parser import find_tf_files, parse_directory
from cloud_guard.terraform.rules import ALL_RULES, Rule


def scan_terraform(directory: str | Path, rules: tuple[Rule, ...] = ALL_RULES) -> ScanResult:
    """Scan all .tf files under `directory` and return a ScanResult.

    Raises FileNotFoundError if the directory doesn't exist (the CLI turns that
    into exit code 2, distinct from "findings found").
    """
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"Not a directory: {root}")

    files = find_tf_files(root)
    result = ScanResult(target=f"terraform {root.as_posix()} ({len(files)} .tf file(s))")
    blocks, errors = parse_directory(root)
    for file_name, message in errors:
        result.skipped.append(SkippedCheck(check_id=f"parse:{file_name}", reason=message))
    if not files:
        result.skipped.append(SkippedCheck(check_id="terraform", reason="no .tf files found"))
        return result

    for rule in rules:
        result.checks_run += 1
        result.findings.extend(rule(blocks))
    return result
