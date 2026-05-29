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


def _verify_bearer_token(authorization: str | None) -> bool:
    """Return True iff *authorization* is a valid ``Bearer <SSF_WEBHOOK_TOKEN>`` header."""
    if not authorization:
        return False
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return False
    expected = settings.ssf_webhook_token
    if not expected:
        return False
    return hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))


def _verify_hmac_signature(raw_body: bytes, signature: str | None) -> bool:
    """Return True iff *signature* is a valid HMAC-SHA256 of *raw_body*."""
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
    """Receive an Authentik webhook event, verify authentication, and push
    matching Security Event Tokens to all enabled SSF streams.

    Returns a JSON object with ``status`` and optional ``delivered``/``failed``
    counts.  Non-fatal conditions (no stream, unmapped event) return
    ``{"status": "ignored", "reason": "..."}``.
    """
    # ------------------------------------------------------------------ #
    # 1. Body size guard                                                   #
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
            pass  # malformed Content-Length — streaming check will catch oversized bodies

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
    # 2. Authentication                                                    #
    # ------------------------------------------------------------------ #
    mode = settings.ssf_webhook_auth_mode

    if mode == "bearer":
        authorization = request.headers.get("Authorization")
        if not _verify_bearer_token(authorization):
            logger.warning("Rejected Authentik webhook: invalid or missing bearer token")
            raise HTTPException(status_code=401, detail="Unauthorized")

    elif mode == "hmac":
        signature = request.headers.get("X-Authentik-Signature")
        if not _verify_hmac_signature(raw_body, signature):
            logger.warning("Rejected Authentik webhook: invalid or missing HMAC signature")
            raise HTTPException(status_code=401, detail="Unauthorized")

    elif mode == "unsigned":
        logger.warning(
            "Authentik webhook accepted without authentication "
            "(SSF_WEBHOOK_AUTH_MODE=unsigned — development/lab only, do not use in production)"
        )

    else:
        logger.error("Invalid SSF_WEBHOOK_AUTH_MODE=%r — rejecting request", mode)
        raise HTTPException(status_code=500, detail="Invalid webhook auth configuration")

    # ------------------------------------------------------------------ #
    # 3. JSON parsing                                                      #
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
    # 4. Event processing                                                  #
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
        for event in events:
            if await push_set(stream, event, email):
                delivered += 1
            else:
                failed += 1

    return {"status": "ok", "delivered": delivered, "failed": failed}
