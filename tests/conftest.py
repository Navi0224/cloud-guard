"""Shared pytest fixtures.

Every AWS test runs inside moto's mock_aws(), with dummy credentials forced
into the environment, so the suite can never reach a real AWS account.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator

import boto3
import pytest
from moto import mock_aws

from cloud_guard.aws.context import AwsContext
from cloud_guard.demo import fake_session

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make sure no real credentials/profile can leak into tests."""
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture
def session() -> Iterator[boto3.session.Session]:
    """A boto3 session whose calls are all answered by moto."""
    with mock_aws():
        yield fake_session(REGION)


@pytest.fixture
def make_ctx(session: boto3.session.Session) -> Callable[..., AwsContext]:
    """Factory: make_ctx(days_ahead=0) -> AwsContext with an optionally shifted clock."""

    def _make(days_ahead: int = 0) -> AwsContext:
        now = datetime.now(timezone.utc) + timedelta(days=days_ahead)
        return AwsContext(session=session, region=REGION, now=now)

    return _make


def ids(findings) -> list[str]:
    """Sorted finding ids - makes assertions short and readable."""
    return sorted(f.id for f in findings)
