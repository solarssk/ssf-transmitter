"""Webhook alerting for Apple SCIM operational events.

Sends a JSON POST to APPLE_SCIM_ALERT_WEBHOOK_URL when re-authorization
is needed or when the client_secret appears to have expired.

Compatible with Ntfy, Slack incoming webhooks, n8n, Make, Uptime Kuma push, etc.
Rate-limited to one alert per event type per hour so a broken sync loop
does not spam the webhook on every cycle.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

import httpx

logger = logging.getLogger(__name__)


ALERT_COOLDOWN = 3600  # seconds — one alert per event type per hour

_last_sent: dict[str, float] = {}


async def send_alert(event: str, message: str, severity: str = "error") -> None:
    """POST an alert to the configured webhook URL.

    Silently returns (with a log at DEBUG level) when:
    - APPLE_SCIM_ALERT_WEBHOOK_URL is not configured
    - The same event was already sent within the last hour
    Never raises — a failed alert must not crash the caller.
    """
    from app.config import settings  # late import avoids circular dependency at module load

    url = settings.apple_scim_alert_webhook_url
    if not url:
        return

    now = time.monotonic()
    if now - _last_sent.get(event, 0) < ALERT_COOLDOWN:
        logger.debug("Alert suppressed (cooldown) event=%s", event)
        return

    payload = {
        "event": event,
        "severity": severity,
        "message": message,
        "authorize_url": settings.public_url("/apple-scim/authorize"),
        "timestamp": datetime.now(UTC).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
        _last_sent[event] = now  # server reached — start cooldown
        if resp.status_code >= 300:
            logger.warning(
                "Alert webhook returned non-2xx status=%s event=%s", resp.status_code, event
            )
        else:
            logger.info("Alert sent event=%s severity=%s", event, severity)
    except httpx.HTTPError:
        logger.warning("Alert webhook unreachable event=%s", event, exc_info=True)
    except Exception:
        logger.warning("Alert webhook unexpected error event=%s", event, exc_info=True)
