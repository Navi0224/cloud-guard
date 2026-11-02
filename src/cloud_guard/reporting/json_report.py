"""Machine-readable JSON output (for pipelines, dashboards, or jq)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from cloud_guard import __version__
from cloud_guard.cis import BENCHMARK
from cloud_guard.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Serialise a ScanResult with a little metadata about the run."""
    payload = {
        "tool": "cloud-guard",
        "version": __version__,
        "benchmark": BENCHMARK,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **result.to_dict(),
    }
    return json.dumps(payload, indent=2)
