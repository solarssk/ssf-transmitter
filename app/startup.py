"""Startup preflight checks for SSF Transmitter.

Runs before the application accepts requests.  Each check is logged with a
clear ✅ / ⚠️ / ❌ prefix.  If any check fails (❌), the process exits with
code 0 so Docker's ``restart: unless-stopped`` policy does NOT restart the
container — the operator must fix the configuration and start it manually.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx

from app.config import settings

logger = logging.getLogger("app.startup")

_OK = "  ✅"
_WARN = "  ⚠️ "
_FAIL = "  ❌"

_VERSION = os.getenv("APP_VERSION", "dev")


def _check_authentik_connectivity() -> None:
    """Probe Authentik API to verify URL and token are correct.

    Non-fatal — logs ✅/⚠️/❌ but never exits. SCIM sync will surface errors
    later if the connection is broken.
    """
    url = f"{settings.authentik_url}/api/v3/core/users/?page_size=1"
    try:
        r = httpx.get(
            url,
            headers={"Authorization": f"Bearer {settings.authentik_token}"},
            timeout=5.0,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        logger.warning("%s Authentik API          unreachable (%s) — check AUTHENTIK_URL", _WARN, exc)
        return

    if r.status_code == 200:
        try:
            count = r.json().get("pagination", {}).get("count", "?")
        except Exception:
            logger.debug("Authentik API response is not JSON: %s", r.text[:200])
            count = "?"
        logger.info("%s Authentik API          %s (connected, %s users)", _OK, settings.authentik_url, count)
    elif r.status_code in (401, 403):
        logger.error("%s Authentik API          %s — check AUTHENTIK_TOKEN", _FAIL, r.status_code)
    else:
        logger.warning("%s Authentik API          unexpected status %s", _WARN, r.status_code)


def run_preflight_checks() -> None:
    """Run all startup checks and exit with code 0 if any critical check fails."""
    logger.info("── SSF Transmitter preflight  v%s ──", _VERSION)
    failed = False

    # ------------------------------------------------------------------ #
    # Environment / config                                                 #
    # ------------------------------------------------------------------ #

    # SSF_ISSUER
    if settings.ssf_issuer:
        logger.info("%s SSF_ISSUER            %s", _OK, settings.ssf_issuer)
        if not settings.ssf_allow_custom_issuer:
            if settings.ssf_issuer.rstrip("/") != settings.ssf_base_url.rstrip("/"):
                logger.warning(
                    "%s SSF_ISSUER            differs from SSF_BASE_URL — receivers may fail "
                    "to validate SETs; set SSF_ALLOW_CUSTOM_ISSUER=true to suppress this warning",
                    _WARN,
                )
            if "/application/o/" in settings.ssf_issuer:
                logger.warning(
                    "%s SSF_ISSUER            looks like an Authentik OIDC application URL — "
                    "SSF_ISSUER should be the transmitter's public base URL (usually SSF_BASE_URL)",
                    _WARN,
                )
    else:
        logger.error("%s SSF_ISSUER            NOT SET", _FAIL)
        failed = True

    # SSF_BASE_URL
    if settings.ssf_base_url:
        logger.info("%s SSF_BASE_URL           %s", _OK, settings.ssf_base_url)
    else:
        logger.error("%s SSF_BASE_URL           NOT SET", _FAIL)
        failed = True

    # SSF_MANAGEMENT_TOKEN
    token_len = len(settings.ssf_management_token) if settings.ssf_management_token else 0
    if token_len >= 32:
        logger.info("%s SSF_MANAGEMENT_TOKEN   configured (%d chars)", _OK, token_len)
    else:
        logger.error("%s SSF_MANAGEMENT_TOKEN   too short (%d chars, min 32)", _FAIL, token_len)
        failed = True

    # SSF_WEBHOOK_AUTH_MODE + token
    mode = settings.ssf_webhook_auth_mode
    if mode == "bearer":
        wt_len = len(settings.ssf_webhook_token) if settings.ssf_webhook_token else 0
        if wt_len >= 32:
            logger.info("%s SSF_WEBHOOK_AUTH_MODE  bearer", _OK)
            logger.info("%s SSF_WEBHOOK_TOKEN      configured (%d chars)", _OK, wt_len)
        else:
            logger.info("%s SSF_WEBHOOK_AUTH_MODE  bearer", _OK)
            logger.error("%s SSF_WEBHOOK_TOKEN      %s",
                         _FAIL, f"too short ({wt_len} chars, min 32)" if wt_len else "NOT SET")
            failed = True
    elif mode == "hmac":
        # Config contract (_parse_webhook_secret) only requires non-empty in hmac mode.
        # Align preflight with that contract — don't add a stricter rule here.
        ws_len = len(settings.ssf_webhook_secret) if settings.ssf_webhook_secret else 0
        if ws_len > 0:
            logger.info("%s SSF_WEBHOOK_AUTH_MODE  hmac (legacy)", _OK)
            logger.info("%s SSF_WEBHOOK_SECRET     configured (%d chars)", _OK, ws_len)
        else:
            logger.info("%s SSF_WEBHOOK_AUTH_MODE  hmac (legacy)", _OK)
            logger.error("%s SSF_WEBHOOK_SECRET     NOT SET", _FAIL)
            failed = True
    elif mode == "unsigned":
        logger.warning("%s SSF_WEBHOOK_AUTH_MODE  unsigned — NO authentication on webhook (dev/lab only)", _WARN)
    else:
        logger.error("%s SSF_WEBHOOK_AUTH_MODE  unknown value %r", _FAIL, mode)
        failed = True

    # ------------------------------------------------------------------ #
    # Local resources                                                      #
    # ------------------------------------------------------------------ #

    # Signing key
    private_pem = Path(settings.keys_dir) / "private.pem"
    if private_pem.exists():
        logger.info("%s Signing key            %s (exists)", _OK, private_pem)
    else:
        # Missing key is not fatal at preflight — ensure_keys() will generate it.
        # Only warn; if generation is also broken it will surface as an exception.
        logger.warning("%s Signing key            %s not found — will be generated on first start",
                       _WARN, private_pem)

    # JWKS
    jwks_path = Path(settings.keys_dir) / "jwks.json"
    if jwks_path.exists():
        logger.info("%s JWKS                   %s (exists)", _OK, jwks_path)
    else:
        logger.warning("%s JWKS                   %s not found — will be generated on first start",
                       _WARN, jwks_path)

    # Database directory
    db_path = Path(settings.database_path)
    db_dir = db_path.parent
    if not db_dir.exists():
        # Directory will be created by init_db(); warn but don't fail.
        logger.warning("%s Database dir           %s does not exist yet — will be created on start",
                       _WARN, db_dir)
    elif not os.access(db_dir, os.W_OK):
        logger.error("%s Database dir           %s is not writable — check volume permissions", _FAIL, db_dir)
        failed = True
    elif db_path.exists() and not os.access(db_path, os.W_OK):
        logger.error("%s Database               %s is not writable — run: chown -R 10001:10001 %s",
                     _FAIL, db_path, db_dir)
        failed = True
    else:
        status = "exists" if db_path.exists() else "will be created"
        logger.info("%s Database               %s (%s)", _OK, db_path, status)

    # ------------------------------------------------------------------ #
    # Optional features                                                    #
    # ------------------------------------------------------------------ #

    if settings.apple_scim_enabled:
        logger.info("%s Apple SCIM             enabled (sync every %ds)",
                    _OK, settings.apple_scim_sync_interval)
        _check_authentik_connectivity()
    else:
        missing = [
            name for name, val in [
                ("APPLE_SCIM_CLIENT_ID", settings.apple_scim_client_id),
                ("APPLE_SCIM_CLIENT_SECRET", settings.apple_scim_client_secret),
                ("AUTHENTIK_URL", settings.authentik_url),
                ("AUTHENTIK_TOKEN", settings.authentik_token),
            ] if not val
        ]
        logger.warning("%s Apple SCIM             disabled — missing: %s", _WARN, ", ".join(missing))

    # ------------------------------------------------------------------ #
    # Result                                                               #
    # ------------------------------------------------------------------ #

    if failed:
        logger.critical(
            "Preflight failed — fix the errors above and restart the container. "
            "The container will NOT restart automatically."
        )
        import sys
        sys.exit(0)  # exit 0 → Docker restart: unless-stopped does NOT restart

    logger.info("── preflight OK — starting ──")
