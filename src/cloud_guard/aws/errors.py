"""Classify AWS errors so we can skip a check gracefully instead of crashing.

Two kinds of "expected" failure exist when scanning a real account:
  1. Permission denied - the scanning role lacks a read permission.
  2. Not supported - the API isn't available (region not enabled, or moto
     doesn't implement it in tests).
Both should produce a *skipped* entry in the report, not a stack trace.
"""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError

ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
}

NOT_SUPPORTED_CODES = {
    "NotImplemented",
    "InvalidAction",
    "OptInRequired",
    "UnsupportedOperation",
}


def error_code(exc: ClientError) -> str:
    """Pull the AWS error code (e.g. 'AccessDenied') out of a ClientError."""
    return str(exc.response.get("Error", {}).get("Code", "Unknown"))


def describe_skip_reason(exc: Exception) -> str:
    """Turn an exception into a short, human-readable reason for the report."""
    if isinstance(exc, ClientError):
        code = error_code(exc)
        if code in ACCESS_DENIED_CODES:
            return f"permission denied ({code}) - see docs for the read-only IAM policy"
        if code in NOT_SUPPORTED_CODES:
            return f"API not supported here ({code})"
        return f"AWS error {code}"
    if isinstance(exc, NotImplementedError):
        # moto raises this for APIs it has not implemented.
        return "API not implemented by this backend (e.g. moto)"
    if isinstance(exc, EndpointConnectionError):
        return "could not reach the AWS endpoint (region disabled or offline?)"
    if isinstance(exc, BotoCoreError):
        return f"botocore error: {exc.__class__.__name__}"
    return f"unexpected error: {exc.__class__.__name__}: {exc}"
