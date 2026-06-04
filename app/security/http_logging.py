"""Helpers for logging HTTP failures without leaking response bodies.

Upstream OAuth/SCIM APIs may include access tokens, refresh tokens, bearer
credentials, emails, or other PII in error payloads.  Log only metadata that is
useful for correlation/debugging and never the raw response body.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

import httpx


def response_metadata(response: httpx.Response) -> dict[str, int | str | None]:
    """Return non-sensitive metadata for an upstream HTTP response."""
    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type"),
        "body_len": len(response.content),
        "body_sha256_8": hashlib.sha256(response.content).hexdigest()[:8],
    }


def json_key_summary(value: object) -> str:
    """Return a safe summary of JSON shape without values.

    This is intended for logs/errors where the JSON object may contain secrets.
    """
    if isinstance(value, Mapping):
        keys = sorted(str(key) for key in value)
        return f"object_keys={keys}"
    if isinstance(value, list):
        return f"list_len={len(value)}"
    return f"type={type(value).__name__}"
