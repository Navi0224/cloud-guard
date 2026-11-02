"""Output formats. Each renderer takes a ScanResult and returns a string."""

from __future__ import annotations

from typing import Callable

from cloud_guard.models import ScanResult
from cloud_guard.reporting.console import render_table
from cloud_guard.reporting.documents import render_html, render_markdown
from cloud_guard.reporting.json_report import render_json

RENDERERS: dict[str, Callable[[ScanResult], str]] = {
    "table": render_table,
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
}

__all__ = ["RENDERERS", "render_table", "render_json", "render_markdown", "render_html"]
