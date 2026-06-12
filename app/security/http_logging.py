"""Helpers for logging HTTP failures without leaking response bodies.

Upstream OAuth/SCIM APIs may include access tokens, refresh tokens, bearer
credentials, emails, or other PII in error payloads.  Log only metadata that is
useful for correlation/debugging and never the raw response body.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

import httpx

from app.security.pii import mask_email

_SENSITIVE_KEYS = {
    "access_token",
    "refresh_token",
    "token",
    "client_secret",
    "authorization",
    "secret",
    "id_token",
}
_EMAIL_RE = re.compile(r"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)


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


def redact_text(text: str, *, log_pii: bool, pii_key: str = "") -> str:
    """Redact emails from free-form text while preserving non-PII diagnostics."""
    def _replace(match: re.Match[str]) -> str:
        return mask_email(match.group(1), log_pii=log_pii, pii_key=pii_key)

    return _EMAIL_RE.sub(_replace, text)


def safe_response_body_text(
    response: httpx.Response,
    *,
    log_pii: bool,
    pii_key: str = "",
    limit: int = 512,
) -> str:
    """Return a redacted, bounded preview of an HTTP response body for logs."""
    raw_text = response.text
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return redact_text(raw_text[:limit], log_pii=log_pii, pii_key=pii_key)

    def _sanitize(value: object) -> object:
        if isinstance(value, Mapping):
            sanitized: dict[str, object] = {}
            for key, nested in value.items():
                key_text = str(key)
                if key_text.lower() in _SENSITIVE_KEYS:
                    sanitized[key_text] = "[redacted]"
                else:
                    sanitized[key_text] = _sanitize(nested)
            return sanitized
        if isinstance(value, list):
            return [_sanitize(item) for item in value]
        if isinstance(value, str):
            return redact_text(value, log_pii=log_pii, pii_key=pii_key)
        return value

    sanitized = json.dumps(_sanitize(parsed), ensure_ascii=True, sort_keys=True)
    return sanitized[:limit]
