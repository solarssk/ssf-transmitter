"""Map Authentik webhook payloads to SSF/CAEP/RISC Security Event types."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"


@dataclass(frozen=True)
class MappedEvent:
    """A single SSF event derived from an Authentik webhook payload."""

    uri: str
    payload: dict[str, Any]
    txn: str | None = None


def _event_timestamp() -> int:
    """Return the current Unix timestamp for CAEP event payloads."""
    return int(time.time())


def _extract_body(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the nested 'body' object, falling back to the top-level
    payload when 'body' is absent or not itself an object.

    Some Authentik webhook shapes send fields at the top level instead of
    nested under 'body'. A plain `payload.get("body") or payload` handled
    that fallback but not the case where 'body' is *present* with the wrong
    JSON type (e.g. `{"body": 1}`) — `.get()` on that would raise instead
    of falling back, so this checks the type explicitly.
    """
    raw_body = payload.get("body")
    return raw_body if isinstance(raw_body, dict) else payload


def _nested_dict(container: dict[str, Any], key: str) -> dict[str, Any]:
    """Return container[key] if it's a dict, else {}.

    Guards 'context'/'user' the same way _extract_body guards 'body' — a
    webhook payload where a reserved key holds a truthy non-dict value must
    not crash extraction, just yield nothing for that key.
    """
    value = container.get(key)
    return value if isinstance(value, dict) else {}


def map_authentik_event(payload: dict[str, Any]) -> list[MappedEvent]:
    """Translate an Authentik webhook body into zero or more SSF mapped events."""
    body = _extract_body(payload)
    action = body.get("action")
    context = _nested_dict(body, "context")
    txn = extract_source_txn(payload)

    if action == "authentik.core.auth.login_failed":
        logger.info("Skipping Authentik event action=%s reason=login_failed", action)
        return []
    if action == "authentik.core.auth.logout":
        return [
            MappedEvent(
                uri=SESSION_REVOKED,
                payload={
                    "event_timestamp": _event_timestamp(),
                    "initiating_entity": "policy",
                    "reason_admin": {"en": "Session revoked in Authentik"},
                },
                txn=txn,
            )
        ]
    if action == "authentik.core.user.delete":
        logger.info("Skipping Authentik event action=%s reason=event_not_supported", action)
        return []
    if action != "authentik.core.user.write":
        logger.warning("Unmapped Authentik event action=%s", action)
        return []

    events: list[MappedEvent] = []
    changed_fields = context.get("changed_fields")
    if not isinstance(changed_fields, list):
        changed_fields = []
    if "password" in changed_fields:
        events.append(
            MappedEvent(
                uri=CREDENTIAL_CHANGE,
                payload={
                    "event_timestamp": _event_timestamp(),
                    "initiating_entity": "user",
                    "credential_type": "password",
                    "change_type": "update",
                    "reason_admin": {"en": "Password changed in Authentik"},
                },
                txn=txn,
            )
        )

    if "is_active" in changed_fields:
        logger.info(
            "Skipping Authentik account state change action=%s reason=event_not_supported is_active=%s",
            action,
            context.get("is_active"),
        )

    if not events:
        logger.warning("Authentik user.write event did not map to SSF event changed_fields=%s", changed_fields)

    return events


def extract_email(payload: dict[str, Any]) -> str | None:
    """Return a normalized email from an Authentik webhook payload, or None."""
    body = _extract_body(payload)
    user = _nested_dict(body, "user")
    raw = user.get("email")
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        return None
    normalized = raw.strip()
    return normalized or None


def extract_action(payload: dict[str, Any]) -> str | None:
    """Return the Authentik action string from a webhook payload."""
    body = _extract_body(payload)
    return body.get("action")


def extract_source_txn(payload: dict[str, Any]) -> str | None:
    """Extract a transaction ID from the Authentik event for use as SET txn.

    Uses the Authentik event pk (UUID) when present so that multiple SETs
    produced from a single webhook share the same txn value.

    pk/event_uuid/request_id are all attacker-suppliable JSON values, not
    guaranteed strings (e.g. a numeric pk) — coerce to match this
    function's own `str | None` contract, otherwise a non-string value
    propagates into SET/JWT claim construction (not JSON-serializable) and
    log calls (sanitize_for_log expects to coerce, but the caller's type
    hint would otherwise lie about what it's passing).
    """
    body = _extract_body(payload)
    for key in ("pk", "event_uuid", "request_id"):
        value = body.get(key)
        if value is not None:
            return str(value)
    return None
