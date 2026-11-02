"""Load Terraform (.tf) files into simple Python objects.

We use python-hcl2 to parse HCL into dicts. We do NOT run `terraform plan`, so
variables, modules and functions are not evaluated - this is pure static
analysis of the source text (fast, needs no cloud credentials, but cannot see
values that are only known at plan time).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hcl2
from hcl2.utils import SerializationOptions

# Ask python-hcl2 for plain values: no surrounding quotes on strings, heredocs
# returned as their text, and no "__is_block__" markers.
_HCL_OPTIONS = SerializationOptions(
    with_comments=False,
    strip_string_quotes=True,
    preserve_heredocs=False,
    explicit_blocks=False,
)

SKIP_DIRS = {".terraform", ".git", "node_modules"}


@dataclass(frozen=True)
class TerraformBlock:
    """One `resource` or `data` block from a .tf file."""

    kind: str  # "resource" or "data"
    type: str  # e.g. "aws_s3_bucket"
    name: str  # e.g. "logs"
    body: dict[str, Any]
    file: str  # path relative to the scanned directory

    @property
    def address(self) -> str:
        """Terraform-style address, e.g. aws_s3_bucket.logs or data.aws_iam_policy_document.x."""
        prefix = "data." if self.kind == "data" else ""
        return f"{prefix}{self.type}.{self.name}"

    @property
    def location(self) -> str:
        """What we show as the 'resource' in a finding: file plus address."""
        return f"{self.file}:{self.address}"


def as_list(value: Any) -> list[Any]:
    """HCL blocks can appear once (dict) or many times (list). Always give a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _clean(value: Any) -> Any:
    """Defensive clean-up in case a different python-hcl2 version adds markers."""
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if not str(k).startswith("__")}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _blocks_from_document(doc: dict[str, Any], rel_path: str) -> list[TerraformBlock]:
    """Flatten {"resource": [{type: {name: body}}]} into TerraformBlock objects."""
    blocks: list[TerraformBlock] = []
    for kind in ("resource", "data"):
        for entry in as_list(doc.get(kind)):
            for rtype, named in entry.items():
                for name, body in named.items():
                    blocks.append(TerraformBlock(kind, rtype, name, _clean(body) or {}, rel_path))
    return blocks


def find_tf_files(directory: Path) -> list[Path]:
    """All .tf files under `directory`, skipping .terraform caches, in stable order."""
    return sorted(
        p for p in directory.rglob("*.tf")
        if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)
    )


def parse_directory(directory: Path) -> tuple[list[TerraformBlock], list[tuple[str, str]]]:
    """Parse every .tf file. Returns (blocks, errors) where errors are (file, message).

    A syntax error in one file must not stop the scan of the others, so errors
    are collected and reported as skipped files.
    """
    blocks: list[TerraformBlock] = []
    errors: list[tuple[str, str]] = []
    for path in find_tf_files(directory):
        rel = path.relative_to(directory).as_posix()
        try:
            with path.open(encoding="utf-8") as handle:
                doc = hcl2.load(handle, serialization_options=_HCL_OPTIONS)
        except Exception as exc:  # noqa: BLE001 - lark raises many error types
            first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
            errors.append((rel, f"could not parse: {first_line}"))
            continue
        blocks.extend(_blocks_from_document(doc, rel))
    return blocks, errors
