"""Core data types shared by the AWS scanner, the Terraform scanner and the reports.

Keeping these in one small module means every scanner produces exactly the same
shape of result, so the reporting code never needs to know *where* a finding
came from.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    """How bad a finding is. The integer value gives us ordering for --fail-on."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Parse a case-insensitive severity name such as 'high'."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"Unknown severity '{value}'. Valid: {valid}") from exc

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.value >= other.value

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.value > other.value

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.value <= other.value

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.value < other.value


@dataclass(frozen=True)
class Finding:
    """One security problem found on one resource.

    Attributes:
        id: Stable check identifier, e.g. "CG-IAM-002" or "TF-S3-001".
        title: Short human-readable description of the problem.
        severity: How urgent it is.
        resource: AWS ARN (live scan) or "file.tf:resource_type.name" (Terraform).
        cis: CIS AWS Foundations Benchmark reference, or a note when there is
            no direct control. See cis.py for the benchmark version.
        remediation: What to do about it, in plain English.
        details: Extra context (e.g. the offending port) - free text.
    """

    id: str
    title: str
    severity: Severity
    resource: str
    cis: str
    remediation: str
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict (Severity becomes its name)."""
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


@dataclass(frozen=True)
class SkippedCheck:
    """A check that could not run (permission denied, unsupported service...).

    We record these instead of crashing, and we show them in every report. A
    scanner that silently skips checks gives a false sense of security, so
    being explicit about what was *not* checked is a security feature.
    """

    check_id: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class ScanResult:
    """Everything a scan produced: findings plus the checks that were skipped."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    skipped: list[SkippedCheck] = field(default_factory=list)
    checks_run: int = 0

    def count_by_severity(self) -> dict[str, int]:
        """Return {"CRITICAL": n, "HIGH": n, ...} including zero counts."""
        counts = {sev.name: 0 for sev in sorted(Severity, key=lambda s: -s.value)}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most severe first, then by id and resource."""
        return sorted(self.findings, key=lambda f: (-f.severity.value, f.id, f.resource))

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        """True if any finding is at least as severe as `threshold` (CI gating)."""
        return any(f.severity >= threshold for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "checks_run": self.checks_run,
            "summary": self.count_by_severity(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "skipped": [s.to_dict() for s in self.skipped],
        }
