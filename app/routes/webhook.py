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


def _pii_key() -> str:
    """Return the HMAC key for email pseudonymisation.

    Uses SSF_PII_PEPPER when set; falls back to the management token so there
    is always *some* keying even without a dedicated pepper.
    """
    return settings.pii_pepper or settings.ssf_management_token


@router.post("/webhook/authentik")
async def authentik_webhook(request: Request) -> dict:
    # ------------------------------------------------------------------ #
    # 1. Body size guard — check Content-Length header first for a fast   #
    #    rejection without reading the body, then cap streaming reads.     #
    # ------------------------------------------------------------------ #
    content_length = request.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > _MAX_BODY_BYTES:
                logger.warning(
                    "Rejected Authentik webhook: Content-Length %s exceeds limit %d",
                    content_length,
                    _MAX_BODY_BYTES,
                )
                raise HTTPException(status_code=413, detail="Request body too large")
        except ValueError:
            pass  # malformed Content-Length — proceed; streaming check will catch oversized bodies

    # Stream-accumulate so we never materialise more than _MAX_BODY_BYTES in RAM.
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > _MAX_BODY_BYTES:
            logger.warning(
                "Rejected Authentik webhook: streamed body exceeded limit bytes=>%d limit=%d",
                size,
                _MAX_BODY_BYTES,
            )
            raise HTTPException(status_code=413, detail="Request body too large")
        chunks.append(chunk)
    raw_body = b"".join(chunks)

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
    # 3. JSON parsing — return 400 on malformed or non-object JSON.        #
    # ------------------------------------------------------------------ #
    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Rejected Authentik webhook: malformed JSON error=%s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
    if not isinstance(payload, dict):
        logger.warning("Rejected Authentik webhook: JSON body is not an object type=%s", type(payload).__name__)
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # ------------------------------------------------------------------ #
    # 4. Event processing.                                                 #
    # ------------------------------------------------------------------ #
    action = extract_action(payload)
    email = extract_email(payload)
    events = map_authentik_event(payload)
    safe_email = mask_email(email, log_pii=settings.log_pii, pii_key=_pii_key())
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
