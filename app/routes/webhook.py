"""Authentik webhook receiver and SSF event dispatch."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.database import Stream, list_streams
from app.events.mapper import MappedEvent, extract_action, extract_email, map_authentik_event
from app.events.pusher import push_set
from app.rate_limit import limiter
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


async def _read_body_within_limit(request: Request) -> bytes:
    """Read the request body, rejecting it if it exceeds `_MAX_BODY_BYTES`."""
    content_length = request.headers.get("Content-Length")
    if content_length is not None:
        try:
            declared_oversized = int(content_length) > _MAX_BODY_BYTES
        except ValueError:
            declared_oversized = False  # malformed — streaming check below will catch it
        if declared_oversized:
            logger.warning(
                "Rejected Authentik webhook: Content-Length %s exceeds limit %d",
                content_length,
                _MAX_BODY_BYTES,
            )
            raise HTTPException(status_code=413, detail="Request body too large")

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
    return b"".join(chunks)


def _authenticate_webhook(request: Request, raw_body: bytes) -> None:
    """Verify the webhook request against the configured SSF_WEBHOOK_AUTH_MODE."""
    mode = settings.ssf_webhook_auth_mode

    if mode == "bearer":
        authorization = request.headers.get("Authorization")
        if not _verify_bearer_token(authorization):
            logger.warning("Rejected Authentik webhook: invalid or missing bearer token")
            raise HTTPException(status_code=401, detail="Unauthorized")
        return

    if mode == "hmac":
        signature = request.headers.get("X-Authentik-Signature")
        if not _verify_hmac_signature(raw_body, signature):
            logger.warning("Rejected Authentik webhook: invalid or missing HMAC signature")
            raise HTTPException(status_code=401, detail="Unauthorized")
        return

    if mode == "unsigned":
        logger.warning(
            "Authentik webhook accepted without authentication "
            "(SSF_WEBHOOK_AUTH_MODE=unsigned — development/lab only, do not use in production)"
        )
        return

    logger.error("Invalid SSF_WEBHOOK_AUTH_MODE=%r — rejecting request", mode)
    raise HTTPException(status_code=500, detail="Invalid webhook auth configuration")


def _parse_webhook_json(raw_body: bytes) -> dict:
    """Parse and validate the webhook body as a JSON object."""
    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Rejected Authentik webhook: malformed JSON error=%s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
    if not isinstance(payload, dict):
        logger.warning("Rejected Authentik webhook: JSON body is not an object type=%s", type(payload).__name__)
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    return payload


async def _dispatch_events(streams: list[Stream], events: list[MappedEvent], email: str | None) -> tuple[int, int]:
    """Push every event to every enabled stream; return (delivered, failed) counts."""
    delivered = 0
    failed = 0
    for stream in streams:
        for event in events:
            result = await push_set(stream, event, email)
            if result is True:
                delivered += 1
            elif result is False:
                failed += 1
            # None = intentionally skipped (not in events_requested) — not a failure
    return delivered, failed


@router.post(
    "/webhook/authentik",
    responses={
        400: {"description": "Malformed JSON body"},
        401: {"description": "Missing or invalid webhook authentication"},
        413: {"description": "Request body too large"},
        500: {"description": "Invalid SSF_WEBHOOK_AUTH_MODE configuration"},
    },
)
@limiter.limit("60/minute")
async def authentik_webhook(request: Request) -> dict:
    """Receive an Authentik webhook event, verify authentication, and push
    matching Security Event Tokens to all enabled SSF streams.

    Returns a JSON object with ``status`` and optional ``delivered``/``failed``
    counts.  Non-fatal conditions (no stream, unmapped event) return
    ``{"status": "ignored", "reason": "..."}``.
    """
    raw_body = await _read_body_within_limit(request)
    _authenticate_webhook(request, raw_body)
    payload = _parse_webhook_json(raw_body)

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
    if not streams:
        logger.warning(
            "No SSF stream configured for event delivery action=%s email=%s",
            action,
            safe_email,
        )
        return {"status": "ignored", "reason": "no_enabled_stream"}

    delivered, failed = await _dispatch_events(streams, events, email)
    return {"status": "ok", "delivered": delivered, "failed": failed}
