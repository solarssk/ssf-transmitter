"""Apple SCIM OAuth token storage and refresh.

Apple uses authorization_code OAuth flow (interactive — admin logs in once).
After the initial authorization:
- access_token:  short-lived (expiry comes from Apple in the token response)
- refresh_token: used to silently obtain new access tokens without re-logging in

The client_secret set in ABM expires every 6/9/12 months.  When that happens
the admin needs to generate a new one in ABM, update APPLE_SCIM_CLIENT_SECRET,
and visit /apple-scim/authorize once more.
"""

from __future__ import annotations

import logging
import time

import aiosqlite
import httpx

from app.alerts import send_alert
from app.config import settings
from app.security.http_logging import json_key_summary, response_metadata

logger = logging.getLogger(__name__)

APPLE_TOKEN_URL = settings.apple_scim_token_url


async def save_tokens(access_token: str, refresh_token: str | None, expires_in: int) -> None:
    """Persist tokens to the database (upsert — there is always at most one row)."""
    now = int(time.time())
    expires_at = now + expires_in - 60  # 60-second safety margin
    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute(
            """
            INSERT INTO apple_scim_tokens (id, access_token, refresh_token, expires_at, updated_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              access_token = excluded.access_token,
              refresh_token = COALESCE(excluded.refresh_token, refresh_token),
              expires_at    = excluded.expires_at,
              updated_at    = excluded.updated_at
            """,
            (access_token, refresh_token, expires_at, now),
        )
        await db.commit()
    logger.info("Apple SCIM tokens saved expires_at=%s", expires_at)


async def load_tokens() -> dict | None:
    """Return stored tokens as a dict, or None if none have been saved yet."""
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM apple_scim_tokens WHERE id = 1")
        row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def get_valid_access_token() -> str | None:
    """Return a valid access token, refreshing it first if it has expired."""
    tokens = await load_tokens()
    if tokens is None:
        logger.warning("Apple SCIM: no tokens stored — visit /apple-scim/authorize to connect")
        return None

    if int(time.time()) < tokens["expires_at"]:
        return tokens["access_token"]

    logger.info("Apple SCIM: access token expired, refreshing")
    return await _refresh(tokens["refresh_token"])


async def _refresh(refresh_token: str | None) -> str | None:
    """Exchange a refresh token for a new access token."""
    if not refresh_token:
        logger.error("Apple SCIM: no refresh token available — re-authorize at /apple-scim/authorize")
        return None

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                APPLE_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": settings.apple_scim_client_id,
                    "client_secret": settings.apple_scim_client_secret,
                },
            )
    except httpx.HTTPError:
        logger.exception("Apple SCIM: network error during token refresh")
        return None

    if resp.status_code != 200:
        logger.error("Apple SCIM: token refresh failed response=%s", response_metadata(resp))
        try:
            error_code = resp.json().get("error", "")
        except Exception:
            error_code = ""
        if error_code in ("invalid_client", "invalid_grant", "unauthorized_client"):
            await send_alert(
                event="scim_client_secret_expired",
                message=(
                    "Apple SCIM client_secret has expired — "
                    "generate a new secret in Apple Business Manager, "
                    "update APPLE_SCIM_CLIENT_SECRET and re-authorize"
                ),
                severity="critical",
            )
        return None

    try:
        data = resp.json()
    except Exception:
        logger.error("Apple SCIM: token refresh response is not valid JSON response=%s", response_metadata(resp))
        return None

    access_token = data.get("access_token")
    new_refresh = data.get("refresh_token")  # Apple may rotate the refresh token
    raw_expires = data.get("expires_in")

    if not access_token or not isinstance(access_token, str):
        logger.error("Apple SCIM: token refresh response missing access_token %s", json_key_summary(data))
        return None
    try:
        expires_in = int(raw_expires)
        if expires_in <= 0:
            raise ValueError("expires_in must be > 0")
    except (TypeError, ValueError):
        logger.error("Apple SCIM: token refresh response has invalid expires_in=%r — defaulting to 3600", raw_expires)
        expires_in = 3600

    await save_tokens(access_token, new_refresh, expires_in)
    logger.info("Apple SCIM: access token refreshed successfully")
    return access_token
