import logging
from urllib.parse import urlparse

import httpx

from app.crypto import sign_set
from app.database import Stream

logger = logging.getLogger(__name__)


def _safe_host(url: str) -> str:
    """Extract the hostname from a URL for safe logging (no path or token)."""
    parsed = urlparse(url)
    return parsed.netloc or "unknown-host"


async def push_set(stream: Stream, event_uri: str, email: str) -> bool:
    """Sign and push a Security Event Token to the stream's endpoint; returns True on success."""
    if stream.status != "enabled":
        logger.warning("Skipping disabled SSF stream stream_id=%s status=%s", stream.stream_id, stream.status)
        return False

    try:
        token = sign_set(event_uri=event_uri, audience=stream.aud, email=email)
    except Exception:
        logger.exception("Failed to sign SET event_uri=%s aud=%s", event_uri, stream.aud)
        return False

    headers: dict[str, str] = {"Content-Type": "application/secevent+jwt"}
    if stream.endpoint_token:
        headers["Authorization"] = f"Bearer {stream.endpoint_token}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(stream.endpoint_url, content=token, headers=headers)
    except httpx.HTTPError:
        logger.exception(
            "Failed to push SET event_uri=%s aud=%s endpoint_host=%s",
            event_uri,
            stream.aud,
            _safe_host(stream.endpoint_url),
        )
        return False

    if response.status_code >= 400:
        logger.warning(
            "Receiver returned error for SET event_uri=%s aud=%s endpoint_host=%s status_code=%s",
            event_uri,
            stream.aud,
            _safe_host(stream.endpoint_url),
            response.status_code,
        )
        return False

    logger.info(
        "Pushed SET event_uri=%s aud=%s endpoint_host=%s status_code=%s",
        event_uri,
        stream.aud,
        _safe_host(stream.endpoint_url),
        response.status_code,
    )
    return True
