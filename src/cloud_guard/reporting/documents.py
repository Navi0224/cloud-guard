"""Human-readable reports: Markdown (for PR comments / GitHub job summaries) and HTML.

Every value that came from the scanned environment is escaped before being put
into HTML. Resource names are attacker-controllable (anyone who can create a
bucket or security group chooses its name), so an unescaped report would be an
XSS vector - a nice example of treating scan data as untrusted input.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from cloud_guard import __version__
from cloud_guard.cis import BENCHMARK
from cloud_guard.models import ScanResult

SEVERITY_COLOURS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
    "INFO": "#4b5563",
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _md_cell(text: str) -> str:
    """Escape characters that would break a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    """Markdown report with a severity summary, a findings table and remediation."""
    out = [
        "# cloud-guard report",
        "",
        f"- **Target:** {_md_cell(result.target)}",
        f"- **Generated:** {_timestamp()} by cloud-guard {__version__}",
        f"- **Mapped to:** {BENCHMARK} (see README for mapping caveats)",
        f"- **Checks run:** {result.checks_run}",
        "",
        "## Summary by severity",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    out += [f"| {sev} | {n} |" for sev, n in result.count_by_severity().items()]
    out += ["", "## Findings", ""]
    if not result.findings:
        out.append("No findings.")
    else:
        out += ["| Severity | ID | Title | Resource | CIS | Remediation |", "|---|---|---|---|---|---|"]
        for f in result.sorted_findings():
            title = f.title + (f" ({f.details})" if f.details else "")
            out.append(
                f"| {f.severity.name} | {f.id} | {_md_cell(title)} | `{_md_cell(f.resource)}` "
                f"| {_md_cell(f.cis)} | {_md_cell(f.remediation)} |"
            )
    if result.skipped:
        out += ["", "## Skipped checks (not evaluated)", ""]
        out += [f"- `{_md_cell(s.check_id)}`: {_md_cell(s.reason)}" for s in result.skipped]
    return "\n".join(out) + "\n"


def render_html(result: ScanResult) -> str:
    """Self-contained HTML report (inline CSS, no JavaScript, no external assets)."""
    esc = html.escape
    summary_cells = "".join(
        f'<div class="card" style="border-color:{SEVERITY_COLOURS[sev]}">'
        f'<div class="n">{n}</div><div>{sev}</div></div>'
        for sev, n in result.count_by_severity().items()
    )
    rows = "".join(
        "<tr>"
        f'<td><span class="sev" style="background:{SEVERITY_COLOURS[f.severity.name]}">{f.severity.name}</span></td>'
        f"<td>{esc(f.id)}</td>"
        f"<td>{esc(f.title)}{'<br><small>' + esc(f.details) + '</small>' if f.details else ''}</td>"
        f"<td><code>{esc(f.resource)}</code></td>"
        f"<td>{esc(f.cis)}</td>"
        f"<td>{esc(f.remediation)}</td>"
        "</tr>"
        for f in result.sorted_findings()
    ) or '<tr><td colspan="6">No findings.</td></tr>'
    skipped = ""
    if result.skipped:
        items = "".join(f"<li><code>{esc(s.check_id)}</code>: {esc(s.reason)}</li>" for s in result.skipped)
        skipped = f"<h2>Skipped checks (not evaluated)</h2><ul>{items}</ul>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>cloud-guard report</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #111827; }}
 .cards {{ display: flex; gap: 1rem; margin: 1rem 0; }}
 .card {{ border-left: 6px solid; padding: .5rem 1rem; background: #f3f4f6; min-width: 6rem; }}
 .card .n {{ font-size: 1.6rem; font-weight: bold; }}
 table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
 th, td {{ border: 1px solid #d1d5db; padding: .4rem; text-align: left; vertical-align: top; }}
 th {{ background: #e5e7eb; }}
 .sev {{ color: #fff; padding: .1rem .4rem; border-radius: 4px; font-size: .8rem; }}
 code {{ word-break: break-all; }}
</style>
</head>
<body>
<h1>cloud-guard report</h1>
<p><b>Target:</b> {esc(result.target)}<br>
<b>Generated:</b> {_timestamp()} by cloud-guard {__version__}<br>
<b>Mapped to:</b> {esc(BENCHMARK)} (see README for mapping caveats)<br>
<b>Checks run:</b> {result.checks_run}</p>
<h2>Summary by severity</h2>
<div class="cards">{summary_cells}</div>
<h2>Findings ({len(result.findings)})</h2>
<table>
<tr><th>Severity</th><th>ID</th><th>Title</th><th>Resource</th><th>CIS</th><th>Remediation</th></tr>
{rows}
</table>
{skipped}
</body>
</html>
"""
