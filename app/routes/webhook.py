from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.database import list_streams
from app.events.mapper import extract_action, extract_email, map_authentik_event
from app.events.pusher import push_set

logger = logging.getLogger(__name__)
router = APIRouter()


def _verify_signature(raw_body: bytes, signature: str | None) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        settings.authentik_webhook_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    provided = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, provided)


@router.post("/webhook/authentik")
async def authentik_webhook(request: Request) -> dict:
    raw_body = await request.body()
    signature = request.headers.get("X-Authentik-Signature")
    if not _verify_signature(raw_body, signature):
        logger.warning("Rejected Authentik webhook due to invalid signature")
        raise HTTPException(status_code=401, detail="Unauthorized")

    payload = await request.json()
    action = extract_action(payload)
    email = extract_email(payload)
    events = map_authentik_event(payload)
    logger.info("Received Authentik webhook action=%s email=%s mapped_events=%s", action, email, len(events))

    if not events:
        return {"status": "ignored", "reason": "unmapped_event"}
    if not email:
        logger.warning("Authentik webhook action=%s mapped but has no user email", action)
        return {"status": "ignored", "reason": "missing_email"}

    streams = await list_streams()
    enabled_streams = [stream for stream in streams if stream.status == "enabled"]
    if not enabled_streams:
        logger.warning("No enabled SSF stream available for event delivery action=%s email=%s", action, email)
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
