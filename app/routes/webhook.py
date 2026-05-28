from __future__ import annotations

import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.database import list_streams
from app.events.mapper import extract_action, extract_email, map_authentik_event
from app.events.pusher import push_set
from app.security.pii import mask_email

logger = logging.getLogger(__name__)
router = APIRouter()

# Reject webhook payloads larger than this to prevent memory exhaustion.
_MAX_BODY_BYTES = 64 * 1024  # 64 KiB


def _verify_signature(raw_body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        settings.ssf_webhook_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    provided = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, provided)


@router.post("/webhook/authentik")
async def authentik_webhook(request: Request) -> dict:
    # ------------------------------------------------------------------ #
    # 1. Body size guard — read raw bytes first to enforce the limit.      #
    # ------------------------------------------------------------------ #
    raw_body = await request.body()
    if len(raw_body) > _MAX_BODY_BYTES:
        logger.warning(
            "Rejected Authentik webhook: body too large bytes=%d limit=%d",
            len(raw_body),
            _MAX_BODY_BYTES,
        )
        raise HTTPException(status_code=413, detail="Request body too large")

    # ------------------------------------------------------------------ #
    # 2. Signature verification.                                           #
    # ------------------------------------------------------------------ #
    signature = request.headers.get("X-Authentik-Signature")

    if signature:
        # Signature present — verify it; reject if invalid
        if not _verify_signature(raw_body, signature):
            logger.warning("Rejected Authentik webhook due to invalid signature")
            raise HTTPException(status_code=401, detail="Unauthorized")
    else:
        # No signature — fail-closed by default; opt out via SSF_ALLOW_UNSIGNED_WEBHOOK=true
        if not settings.allow_unsigned_webhook:
            logger.warning(
                "Rejected Authentik webhook: missing X-Authentik-Signature. "
                "Set SSF_ALLOW_UNSIGNED_WEBHOOK=true to accept unsigned requests (unsafe)."
            )
            raise HTTPException(status_code=401, detail="Unauthorized")
        logger.warning(
            "Authentik webhook accepted without HMAC signature "
            "(SSF_ALLOW_UNSIGNED_WEBHOOK=true — ensure endpoint is internal-network only)"
        )

    # ------------------------------------------------------------------ #
    # 3. JSON parsing — return 400 on malformed JSON.                      #
    # ------------------------------------------------------------------ #
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        logger.warning("Rejected Authentik webhook: malformed JSON error=%s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    # ------------------------------------------------------------------ #
    # 4. Event processing.                                                 #
    # ------------------------------------------------------------------ #
    action = extract_action(payload)
    email = extract_email(payload)
    events = map_authentik_event(payload)
    safe_email = mask_email(email, log_pii=settings.log_pii)
    logger.info(
        "Received Authentik webhook action=%s email=%s mapped_events=%s",
        action,
        safe_email,
        len(events),
    )

    if not events:
        return {"status": "ignored", "reason": "unmapped_event"}
    if not email:
        logger.warning("Authentik webhook action=%s mapped but has no user email", action)
        return {"status": "ignored", "reason": "missing_email"}

    streams = await list_streams()
    enabled_streams = [stream for stream in streams if stream.status == "enabled"]
    if not enabled_streams:
        logger.warning(
            "No enabled SSF stream available for event delivery action=%s email=%s",
            action,
            safe_email,
        )
        return {"status": "ignored", "reason": "no_enabled_stream"}

    delivered = 0
    failed = 0
    for stream in enabled_streams:
        for event_uri in events:
            if await push_set(stream, event_uri, email):
                delivered += 1
            else:
                failed += 1

    return {"status": "ok", "delivered": delivered, "failed": failed}
