"""CLI exit codes (CI gating) and report renderers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloud_guard.cli import main
from cloud_guard.models import Finding, ScanResult, Severity, SkippedCheck
from cloud_guard.reporting import render_html, render_json, render_markdown, render_table

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "terraform"
INSECURE, SECURE = str(EXAMPLES / "insecure"), str(EXAMPLES / "secure")


# ----------------------------------------------------------------- exit codes


@pytest.mark.parametrize("argv,expected", [
    (["scan-terraform", INSECURE], 1),                          # default --fail-on high
    (["scan-terraform", INSECURE, "--fail-on", "none"], 0),
    (["scan-terraform", INSECURE, "--fail-on", "critical"], 1),  # public ACL is CRITICAL
    (["scan-terraform", SECURE], 0),
    (["scan-terraform", SECURE, "--fail-on", "info"], 0),
    (["scan-terraform", "does/not/exist"], 2),
])
def test_exit_codes(argv, expected, capsys):
    assert main(argv) == expected


def test_fail_on_threshold_is_inclusive(tmp_path):
    # Only a MEDIUM finding (TF-EBS-001 + good trail): fails at medium, passes at high.
    (tmp_path / "main.tf").write_text(
        'resource "aws_ebs_volume" "v" {\n size = 1\n}\n'
        'resource "aws_cloudtrail" "t" {\n is_multi_region_trail = true\n enable_log_file_validation = true\n}\n',
        encoding="utf-8",
    )
    assert main(["scan-terraform", str(tmp_path), "--fail-on", "medium"]) == 1
    assert main(["scan-terraform", str(tmp_path), "--fail-on", "high"]) == 0


def test_json_output_is_valid(capsys):
    main(["scan-terraform", INSECURE, "--format", "json", "--fail-on", "none"])
    data = json.loads(capsys.readouterr().out)
    assert data["benchmark"].startswith("CIS AWS Foundations Benchmark")
    assert data["summary"]["CRITICAL"] == 2
    assert {"id", "title", "severity", "resource", "cis", "remediation"} <= set(data["findings"][0])


@pytest.mark.parametrize("fmt,suffix,marker", [("html", "html", "<!DOCTYPE html>"), ("markdown", "md", "# cloud-guard report")])
def test_report_written_to_file(tmp_path, fmt, suffix, marker, capsys):
    out = tmp_path / f"report.{suffix}"
    assert main(["scan-terraform", INSECURE, "--format", fmt, "-o", str(out), "--fail-on", "none"]) == 0
    assert out.read_text(encoding="utf-8").startswith(marker)
    assert "Report written to" in capsys.readouterr().out


def test_demo_command_runs_and_exits_zero_by_default(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "CG-S3-001" in out and "moto mock" in out


def test_demo_can_gate(capsys):
    assert main(["demo", "--fail-on", "critical"]) == 1


# ----------------------------------------------------------------- renderers


def _result_with(resource: str) -> ScanResult:
    finding = Finding("X-1", "Bad thing", Severity.HIGH, resource, "CIS 0.0", "Fix it", "detail")
    return ScanResult(target="t", findings=[finding], skipped=[SkippedCheck("c", "denied")], checks_run=1)


def test_html_escapes_untrusted_resource_names():
    # Resource names are chosen by whoever created the resource -> treat as untrusted.
    html = render_html(_result_with('<script>alert("x")</script>'))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_markdown_escapes_pipes():
    md = render_markdown(_result_with("a|b"))
    assert "a\\|b" in md


def test_all_renderers_show_skipped_checks():
    result = _result_with("arn:aws:s3:::x")
    for render in (render_table, render_markdown, render_html):
        assert "denied" in render(result)
    assert json.loads(render_json(result))["skipped"] == [{"check_id": "c", "reason": "denied"}]


def test_summary_counts_and_ordering():
    result = ScanResult(target="t", findings=[
        Finding("A", "a", Severity.LOW, "r", "", ""),
        Finding("B", "b", Severity.CRITICAL, "r", "", ""),
        Finding("C", "c", Severity.LOW, "r", "", ""),
    ])
    assert result.count_by_severity() == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 2, "INFO": 0}
    assert [f.id for f in result.sorted_findings()] == ["B", "A", "C"]
    assert result.has_findings_at_or_above(Severity.HIGH)
    assert not ScanResult("t", findings=result.findings[:1]).has_findings_at_or_above(Severity.MEDIUM)


def test_severity_parsing():
    assert Severity.from_str(" High ") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.from_str("urgent")
