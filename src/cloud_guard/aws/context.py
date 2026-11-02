"""Shared state passed to every AWS check.

Why a context object? Checks need the same things (a boto3 session, the region,
the account id, "what time is it") and we want tests to be able to swap them.
In particular `now` is injectable so tests can pretend the scan runs 100 days in
the future, which is how we test "access key older than 90 days" without
waiting 90 days or poking at moto internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3

from cloud_guard.models import SkippedCheck


@dataclass
class AwsContext:
    """Everything a check needs to talk to AWS (or to moto)."""

    session: boto3.session.Session
    region: str
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    skipped: list[SkippedCheck] = field(default_factory=list)
    _clients: dict[tuple[str, str], Any] = field(default_factory=dict, repr=False)
    _account_id: str | None = field(default=None, repr=False)

    def client(self, service: str, region: str | None = None) -> Any:
        """Return a cached boto3 client for `service` in `region` (default: scan region)."""
        key = (service, region or self.region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=key[1])
        return self._clients[key]

    @property
    def account_id(self) -> str:
        """The AWS account id of the credentials we're using (one STS call, cached)."""
        if self._account_id is None:
            self._account_id = self.client("sts").get_caller_identity()["Account"]
        return self._account_id

    @property
    def account_arn(self) -> str:
        """ARN representing the account itself, used for account-level settings."""
        return f"arn:aws:iam::{self.account_id}:root"

    def skip(self, check_id: str, reason: str) -> None:
        """Record that (part of) a check could not run, e.g. one bucket was AccessDenied."""
        self.skipped.append(SkippedCheck(check_id=check_id, reason=reason))


def build_session(profile: str | None = None, region: str | None = None) -> tuple[boto3.session.Session, str]:
    """Create a boto3 session from the normal AWS credential chain.

    We never read or store secrets ourselves: boto3 finds credentials in env
    vars, ~/.aws/credentials, SSO, or an instance role. Returns the session and
    the region to scan (falls back to us-east-1 if none is configured).
    """
    session = boto3.session.Session(profile_name=profile, region_name=region)
    return session, session.region_name or "us-east-1"
