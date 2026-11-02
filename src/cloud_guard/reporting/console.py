"""Plain-text table for the terminal.

Deliberately ASCII-only and dependency-free so it renders the same in Windows
PowerShell, cmd.exe, Linux terminals and CI logs.
"""

from __future__ import annotations

from cloud_guard.models import ScanResult

COLUMNS = ("SEVERITY", "ID", "TITLE", "RESOURCE", "CIS")
MAX_WIDTH = {"TITLE": 58, "RESOURCE": 75, "CIS": 22}


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."


def _rows(result: ScanResult) -> list[tuple[str, ...]]:
    rows = []
    for f in result.sorted_findings():
        values = {"SEVERITY": f.severity.name, "ID": f.id, "TITLE": f.title, "RESOURCE": f.resource, "CIS": f.cis}
        rows.append(tuple(_truncate(values[c], MAX_WIDTH.get(c, 999)) for c in COLUMNS))
    return rows


def render_summary(result: ScanResult) -> str:
    """One line like 'CRITICAL: 2  HIGH: 5  MEDIUM: 3  LOW: 1  INFO: 0'."""
    return "  ".join(f"{sev}: {n}" for sev, n in result.count_by_severity().items())


def render_table(result: ScanResult) -> str:
    """Render findings as an aligned text table followed by a severity summary."""
    lines = [f"cloud-guard scan of {result.target}", f"checks run: {result.checks_run}", ""]
    rows = _rows(result)
    if rows:
        widths = [max(len(COLUMNS[i]), *(len(r[i]) for r in rows)) for i in range(len(COLUMNS))]
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        lines.append(fmt.format(*COLUMNS).rstrip())
        lines.append(fmt.format(*("-" * w for w in widths)))
        lines.extend(fmt.format(*row).rstrip() for row in rows)
    else:
        lines.append("No findings.")
    lines += ["", f"Summary ({len(result.findings)} findings)  " + render_summary(result)]
    if result.skipped:
        lines.append("")
        lines.append(f"Skipped ({len(result.skipped)}) - these were NOT checked:")
        lines.extend(f"  - {s.check_id}: {s.reason}" for s in result.skipped)
    return "\n".join(lines)
