import hashlib
import logging
from urllib.parse import urlparse

import httpx
from jose import jwt

from app.crypto import sign_set, sign_verification_set
from app.database import Stream
from app.events.mapper import MappedEvent
from app.security.url_validation import _is_blocked_ip, _resolve_host

logger = logging.getLogger(__name__)


def _safe_host(url: str) -> str:
    """Extract the hostname from a URL for safe logging (no path or token)."""
    parsed = urlparse(url)
    return parsed.netloc or "unknown-host"


def _revalidate_endpoint(url: str) -> bool:
    """Re-resolve endpoint hostname and verify it still points to a public IP.

    Guards against DNS rebinding: a hostname may resolve to a public IP at
    stream creation time and later rebind to a private/metadata address.
    Returns False (and logs a warning) if any resolved IP is blocked.
    """
    host = urlparse(url).hostname or ""
    ips = _resolve_host(host)
    if not ips:
        logger.warning("Blocked outbound push: endpoint_url host %r failed to resolve", host)
        return False
    for ip in ips:
        if _is_blocked_ip(ip):
            logger.warning(
                "Blocked outbound push: endpoint_url host %r re-resolved to blocked IP %r",
                host,
                ip,
            )
            return False
    return True


async def push_set(stream: Stream, event: MappedEvent, email: str) -> bool | None:
    """Sign and push a Security Event Token; returns True on success, False on failure, None if skipped.

    None is returned when the event is intentionally skipped (e.g. not in
    stream.events_requested). Callers must not count None as a delivery failure.
    """
    if stream.status != "enabled":
        logger.warning("Skipping disabled SSF stream stream_id=%s status=%s", stream.stream_id, stream.status)
        return None

    if stream.events_requested and event.uri not in stream.events_requested:
        logger.info(
            "Skipping SET — event URI not in stream.events_requested stream_id=%s event_uri=%s",
            stream.stream_id,
            event.uri,
        )
        return None

    if not _revalidate_endpoint(stream.endpoint_url):
        return False

    try:
        token = sign_set(
            event_uri=event.uri,
            audience=stream.aud,
            email=email,
            event_payload=event.payload,
            txn=event.txn,
        )
    except Exception:
        logger.exception("Failed to sign SET event_uri=%s aud=%s", event.uri, stream.aud)
        return False

    if logger.isEnabledFor(logging.DEBUG):
        try:
            claims = jwt.get_unverified_claims(token)
            safe = {k: v for k, v in claims.items() if k not in ("sub_id", "sub")}
            logger.debug("SET claims event_uri=%s aud=%s payload=%s", event.uri, stream.aud, safe)
        except Exception:
            logger.debug("SET claims could not be decoded event_uri=%s", event.uri)

    headers: dict[str, str] = {
        "Content-Type": "application/secevent+jwt",
        "Accept": "application/json",
    }
    if stream.endpoint_token:
        headers["Authorization"] = f"Bearer {stream.endpoint_token}"

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.post(stream.endpoint_url, content=token, headers=headers)
    except httpx.HTTPError:
        logger.exception(
            "Failed to push SET event_uri=%s aud=%s endpoint_host=%s",
            event.uri,
            stream.aud,
            _safe_host(stream.endpoint_url),
        )
        return False

    if not (200 <= response.status_code < 300):
        body_hash = hashlib.sha256(response.content).hexdigest()[:8]
        logger.warning(
            "Receiver returned error for SET event_uri=%s aud=%s endpoint_host=%s status_code=%s body_hash=%s",
            event.uri,
            stream.aud,
            _safe_host(stream.endpoint_url),
            response.status_code,
            body_hash,
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Receiver error body_hash=%s body_len=%d", body_hash, len(response.content))
        return False

    logger.info(
        "Pushed SET event_uri=%s aud=%s endpoint_host=%s status_code=%s",
        event.uri,
        stream.aud,
        _safe_host(stream.endpoint_url),
        response.status_code,
    )
    return True


async def push_verification_set(stream: "Stream", state: str | None = None) -> bool:
    """Push a verification SET to the stream's endpoint.

    ``state`` is forwarded to the receiver when provided (receiver-initiated
    verification per SSF §6.2). Omitted for transmitter-initiated verification.
    """
    if not _revalidate_endpoint(stream.endpoint_url):
        return False

    try:
        token = sign_verification_set(audience=stream.aud, stream_id=stream.stream_id, state=state)
    except Exception:
        logger.exception("Failed to sign verification SET aud=%s", stream.aud)
        return False

    headers: dict[str, str] = {
        "Content-Type": "application/secevent+jwt",
        "Accept": "application/json",
    }
    if stream.endpoint_token:
        headers["Authorization"] = f"Bearer {stream.endpoint_token}"

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.post(stream.endpoint_url, content=token, headers=headers)
    except httpx.HTTPError:
        logger.exception(
            "Failed to push verification SET aud=%s endpoint_host=%s",
            stream.aud,
            _safe_host(stream.endpoint_url),
        )
        return False

    if not (200 <= response.status_code < 300):
        body_hash = hashlib.sha256(response.content).hexdigest()[:8]
        logger.warning(
            "Receiver rejected verification SET aud=%s endpoint_host=%s status_code=%s body_hash=%s",
            stream.aud,
            _safe_host(stream.endpoint_url),
            response.status_code,
            body_hash,
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Receiver error body_hash=%s body_len=%d", body_hash, len(response.content))
        return False

    logger.info(
        "Pushed verification SET aud=%s endpoint_host=%s status_code=%s",
        stream.aud,
        _safe_host(stream.endpoint_url),
        response.status_code,
    )
    return True
