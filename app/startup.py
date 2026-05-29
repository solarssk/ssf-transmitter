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

from app.config import settings

logger = logging.getLogger("app.startup")

_OK = "  ✅"
_WARN = "  ⚠️ "
_FAIL = "  ❌"


def run_preflight_checks() -> None:
    """Run all startup checks and exit with code 0 if any critical check fails."""
    logger.info("── SSF Transmitter preflight ──")
    failed = False

    # ------------------------------------------------------------------ #
    # Environment / config                                                 #
    # ------------------------------------------------------------------ #

    # SSF_ISSUER
    if settings.ssf_issuer:
        logger.info("%s SSF_ISSUER            %s", _OK, settings.ssf_issuer)
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
        ws_len = len(settings.ssf_webhook_secret) if settings.ssf_webhook_secret else 0
        if ws_len >= 32:
            logger.info("%s SSF_WEBHOOK_AUTH_MODE  hmac (legacy)", _OK)
            logger.info("%s SSF_WEBHOOK_SECRET     configured (%d chars)", _OK, ws_len)
        else:
            logger.info("%s SSF_WEBHOOK_AUTH_MODE  hmac (legacy)", _OK)
            logger.error("%s SSF_WEBHOOK_SECRET     %s",
                         _FAIL, f"too short ({ws_len} chars, min 32)" if ws_len else "NOT SET")
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
        logger.error("%s Database dir           %s does not exist — mount /app/data volume", _FAIL, db_dir)
        failed = True
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
    else:
        logger.warning("%s Apple SCIM             disabled (set APPLE_SCIM_CLIENT_ID, "
                       "APPLE_SCIM_CLIENT_SECRET, AUTHENTIK_URL, AUTHENTIK_TOKEN to enable)", _WARN)

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
