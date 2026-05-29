from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
ACCOUNT_ENABLED = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged"


@dataclass(frozen=True)
class MappedEvent:
    """A single SSF event derived from an Authentik webhook payload."""

    uri: str
    payload: dict[str, Any]
    txn: str | None = None


def _event_timestamp() -> int:
    return int(time.time())


def map_authentik_event(payload: dict[str, Any]) -> list[MappedEvent]:
    body = payload.get("body") or payload
    action = body.get("action")
    context = body.get("context") or {}
    txn = extract_source_txn(payload)

    if action == "authentik.core.auth.login_failed":
        logger.info("Skipping Authentik event action=%s reason=login_failed", action)
        return []
    if action == "authentik.core.auth.logout":
        return [MappedEvent(
            uri=SESSION_REVOKED,
            payload={
                "event_timestamp": _event_timestamp(),
                "initiating_entity": "policy",
                "reason_admin": {"en": "Session revoked in Authentik"},
            },
            txn=txn,
        )]
    if action == "authentik.core.user.delete":
        return [MappedEvent(uri=ACCOUNT_PURGED, payload={}, txn=txn)]
    if action != "authentik.core.user.write":
        logger.warning("Unmapped Authentik event action=%s", action)
        return []

    events: list[MappedEvent] = []
    changed_fields = context.get("changed_fields") or []
    if "password" in changed_fields:
        events.append(MappedEvent(
            uri=CREDENTIAL_CHANGE,
            payload={
                "event_timestamp": _event_timestamp(),
                "initiating_entity": "user",
                "credential_type": "password",
                "change_type": "update",
                "reason_admin": {"en": "Password changed in Authentik"},
            },
            txn=txn,
        ))

    if context.get("is_active") is False:
        events.append(MappedEvent(uri=ACCOUNT_DISABLED, payload={}, txn=txn))
    elif context.get("is_active") is True:
        events.append(MappedEvent(uri=ACCOUNT_ENABLED, payload={}, txn=txn))

    if not events:
        logger.warning("Authentik user.write event did not map to SSF event changed_fields=%s", changed_fields)

    return events


def extract_email(payload: dict[str, Any]) -> str | None:
    body = payload.get("body") or payload
    user = body.get("user") or {}
    return user.get("email")


def extract_action(payload: dict[str, Any]) -> str | None:
    body = payload.get("body") or payload
    return body.get("action")


def extract_source_txn(payload: dict[str, Any]) -> str | None:
    """Extract a transaction ID from the Authentik event for use as SET txn.

    Uses the Authentik event pk (UUID) when present so that multiple SETs
    produced from a single webhook share the same txn value.
    """
    body = payload.get("body") or payload
    return body.get("pk") or body.get("event_uuid") or body.get("request_id") or None
