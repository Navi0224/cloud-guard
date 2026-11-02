"""Helpers for reading IAM and S3 policy documents.

Used by BOTH the live AWS checks and the Terraform checks, so "what counts as an
admin policy" or "what counts as public" is defined in exactly one place.
"""

from __future__ import annotations

import json
from typing import Any, Iterable
from urllib.parse import unquote

PolicyDoc = dict[str, Any]


def _as_list(value: Any) -> list[Any]:
    """IAM lets most fields be a single string OR a list. Normalise to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_policy(document: str | PolicyDoc) -> PolicyDoc:
    """Turn a policy document into a dict.

    boto3 usually decodes IAM policy documents for us, but the raw API returns
    URL-encoded JSON, and S3 bucket policies come back as a JSON string. This
    accepts any of those forms.
    """
    if isinstance(document, dict):
        return document
    text = document.strip()
    if text.startswith("%7B") or text.startswith("%7b"):
        text = unquote(text)
    return json.loads(text)


def statements(policy: PolicyDoc) -> list[dict[str, Any]]:
    """Return the list of statements in a policy (Statement may be one dict)."""
    return [s for s in _as_list(policy.get("Statement")) if isinstance(s, dict)]


def _matches_everything(values: Iterable[Any]) -> bool:
    """True if any entry is a full wildcard ("*" or "*:*" for actions)."""
    return any(str(v).strip() in ("*", "*:*") for v in values)


def is_admin_statement(statement: dict[str, Any]) -> bool:
    """Does this statement grant full administrator access?

    Security reasoning: "Effect: Allow, Action: *, Resource: *" means *every*
    API call on *every* resource. That is the opposite of least privilege and is
    exactly what CIS 1.16 forbids. We deliberately ignore Deny statements (a
    Deny on * is a guard rail, not a risk).

    Limitation: we do not evaluate NotAction/NotResource or Conditions, so a
    policy like "NotAction: iam:*" (almost admin) is not flagged.
    """
    if str(statement.get("Effect", "")).lower() != "allow":
        return False
    actions = _as_list(statement.get("Action"))
    resources = _as_list(statement.get("Resource"))
    return _matches_everything(actions) and _matches_everything(resources)


def has_admin_statement(policy: PolicyDoc) -> bool:
    """True if any statement in the policy is a full-admin statement."""
    return any(is_admin_statement(s) for s in statements(policy))


def _principal_is_everyone(principal: Any) -> bool:
    """True for Principal "*" or {"AWS": "*"} (or a list containing "*")."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any("*" in _as_list(v) for v in principal.values())
    return False


def public_statements(policy: PolicyDoc) -> list[dict[str, Any]]:
    """Return Allow statements that grant access to anyone on the internet.

    A statement with a Condition (e.g. aws:SourceVpce or aws:SourceIp) may be
    restricting access, so we do not count it as public. This mirrors, in a
    simplified way, what AWS's own "policy status" API does.
    """
    public = []
    for stmt in statements(policy):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        if stmt.get("Condition"):
            continue
        if _principal_is_everyone(stmt.get("Principal")):
            public.append(stmt)
    return public
