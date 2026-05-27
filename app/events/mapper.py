from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
ACCOUNT_ENABLED = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged"


def map_authentik_event(payload: dict[str, Any]) -> list[str]:
    body = payload.get("body") or payload
    action = body.get("action")
    context = body.get("context") or {}

    if action == "authentik.core.auth.login_failed":
        logger.info("Skipping Authentik event action=%s reason=login_failed", action)
        return []
    if action == "authentik.core.auth.logout":
        return [SESSION_REVOKED]
    if action == "authentik.core.user.delete":
        return [ACCOUNT_PURGED]
    if action != "authentik.core.user.write":
        logger.warning("Unmapped Authentik event action=%s", action)
        return []

    events = []
    changed_fields = context.get("changed_fields") or []
    if "password" in changed_fields:
        events.append(CREDENTIAL_CHANGE)

    if context.get("is_active") is False:
        events.append(ACCOUNT_DISABLED)
    elif context.get("is_active") is True:
        events.append(ACCOUNT_ENABLED)

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
