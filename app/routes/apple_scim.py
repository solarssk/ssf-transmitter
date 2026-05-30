"""Apple Business Manager — SCIM directory sync routes.

OAuth 2.0 authorization_code flow (Apple is the authorization server):

  1. Admin visits  GET /apple-scim/authorize
     → browser is redirected to Apple's login page

  2. Admin approves the connection on Apple's side
     → Apple redirects browser back to GET /apple-scim/callback?code=XXX&state=XXX

  3. We validate the state, exchange the code for access_token + refresh_token
     and store them.  Sync starts automatically on the next scheduled cycle, or
     immediately via POST /apple-scim/sync.

The client_secret set in ABM expires every 6/9/12 months.  When it does:
  1. Go to ABM → Settings → Directory Sync → generate a new Client Secret
  2. Update APPLE_SCIM_CLIENT_SECRET in your environment / stack.env
  3. Restart the container, then visit /apple-scim/authorize once more
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse

from app.auth import require_management_auth
from app.config import settings
from app.scim.apple import sync_users
from app.scim.authentik import get_users
from app.scim.token import APPLE_TOKEN_URL, get_valid_access_token, load_tokens, save_tokens

logger = logging.getLogger(__name__)

APPLE_AUTH_URL = settings.apple_scim_authorize_url

router = APIRouter(prefix="/apple-scim", tags=["Apple SCIM"])

# In-memory store for pending OAuth state values.  Single-use: consumed on
# callback validation.  A container restart clears them, which is acceptable
# since the admin simply re-visits /authorize.
_pending_states: set[str] = set()

# Holds references to fire-and-forget background tasks so they are not
# garbage-collected before they finish.
_background_tasks: set[asyncio.Task[None]] = set()


def _require_scim_configured() -> None:
    """Raise 503 when required Apple SCIM env vars are not set."""
    if not settings.apple_scim_enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "Apple SCIM sync is not configured. "
                "Set APPLE_SCIM_CLIENT_ID, APPLE_SCIM_CLIENT_SECRET, "
                "AUTHENTIK_URL and AUTHENTIK_TOKEN."
            ),
        )


@router.get("/authorize", summary="Start Apple OAuth to authorize SCIM sync")
async def authorize() -> RedirectResponse:
    """Redirect the admin to Apple's login page to authorize SCIM access.

    Visit this URL once after initial setup and once per year when the
    client secret expires and you have generated a new one in ABM.
    A cryptographically-random ``state`` value is generated and stored
    server-side to prevent CSRF attacks during the OAuth callback.
    """
    _require_scim_configured()
    state = secrets.token_urlsafe(32)
    _pending_states.add(state)
    callback_url = settings.public_url("/apple-scim/callback")
    params = {
        "client_id": settings.apple_scim_client_id,
        "redirect_uri": callback_url,
        "response_type": "code",
        "state": state,
    }
    url = f"{APPLE_AUTH_URL}?{urlencode(params)}"
    logger.info("Apple SCIM: redirecting admin to Apple OAuth callback_url=%s", callback_url)
    return RedirectResponse(url=url)


@router.get("/callback", summary="OAuth callback — Apple redirects here after admin approves")
async def callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> dict:
    """Handle the redirect from Apple after the admin authorizes the connection.

    Apple appends ``?code=XXX&state=YYY`` to this URL.  The ``state`` is
    validated against the value generated in ``/authorize`` to prevent CSRF.
    On success the authorization code is exchanged for tokens which are
    persisted to the database.
    """
    _require_scim_configured()

    if error:
        logger.error("Apple SCIM: OAuth error from Apple error=%s", error)
        raise HTTPException(status_code=400, detail=f"Apple returned an OAuth error: {error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing 'code' parameter in callback")

    # CSRF check — state must match one we issued and be consumed immediately
    if not state or state not in _pending_states:
        logger.warning("Apple SCIM: invalid or missing OAuth state — possible CSRF attempt")
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state parameter")
    _pending_states.discard(state)

    callback_url = settings.public_url("/apple-scim/callback")
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                APPLE_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": callback_url,
                    "client_id": settings.apple_scim_client_id,
                    "client_secret": settings.apple_scim_client_secret,
                },
            )
    except httpx.HTTPError as exc:
        logger.exception("Apple SCIM: network error during code exchange")
        raise HTTPException(status_code=502, detail="Network error contacting Apple token endpoint") from exc

    if resp.status_code != 200:
        logger.error("Apple SCIM: token exchange failed status=%s body=%r", resp.status_code, resp.text[:500])
        raise HTTPException(
            status_code=502,
            detail=f"Apple token endpoint returned {resp.status_code}: {resp.text[:200]}",
        )

    data = resp.json()
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in", 3600)

    if not access_token:
        raise HTTPException(status_code=502, detail=f"Apple did not return an access_token: {data}")

    await save_tokens(access_token, refresh_token, expires_in)
    logger.info(
        "Apple SCIM: authorization complete has_refresh_token=%s expires_in=%s",
        bool(refresh_token), expires_in,
    )

    # Kick off an immediate sync in the background so the admin doesn't have
    # to manually POST /apple-scim/sync after every (re-)authorization.
    async def _background_sync() -> None:
        try:
            users = await get_users()
            if users is not None:
                await sync_users(access_token, users)
        except Exception:
            logger.exception("Apple SCIM: background sync after authorization failed")

    task = asyncio.create_task(_background_sync())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    return {
        "status": "authorized",
        "expires_in": expires_in,
        "has_refresh_token": bool(refresh_token),
        "message": "Authorization successful. Initial sync started automatically.",
    }


@router.get("/status", summary="Show SCIM sync connection status")
async def status() -> dict:
    """Return the current state of the Apple SCIM connection and token validity."""
    if not settings.apple_scim_enabled:
        return {"enabled": False, "reason": "not_configured"}

    tokens = await load_tokens()
    if tokens is None:
        return {
            "enabled": True,
            "authorized": False,
            "reason": "Visit /apple-scim/authorize to connect",
        }

    now = int(time.time())
    token_valid = now < tokens["expires_at"]
    return {
        "enabled": True,
        "authorized": True,
        "token_valid": token_valid,
        "token_expires_at": tokens["expires_at"],
        "token_expires_in_seconds": max(0, tokens["expires_at"] - now),
        "has_refresh_token": bool(tokens.get("refresh_token")),
        "last_updated": tokens["updated_at"],
        "alert_webhook_configured": bool(settings.apple_scim_alert_webhook_url),
    }


@router.post("/sync", summary="Trigger an immediate user sync to Apple Business Manager")
async def sync(_auth: None = Depends(require_management_auth)) -> dict:
    """Fetch users from Authentik and push them to Apple Business Manager via SCIM.

    This runs automatically every APPLE_SCIM_SYNC_INTERVAL seconds (default 1h).
    Call this endpoint to trigger an immediate sync without waiting for the timer.
    """
    _require_scim_configured()

    access_token = await get_valid_access_token()
    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="No valid Apple access token. Visit /apple-scim/authorize to connect.",
        )

    users = await get_users()
    if users is None:
        raise HTTPException(status_code=502, detail="Could not fetch users from Authentik")

    result = await sync_users(access_token, users)
    return {
        "status": "ok",
        "created": result.created,
        "updated": result.updated,
        "unchanged": result.unchanged,
        "errors": result.errors,
    }
