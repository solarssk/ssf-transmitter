"""FastAPI dependency for management API bearer token authentication.

All SSF management endpoints (/ssf/streams, /ssf/status, /apple-scim/sync)
require a Bearer token matching SSF_MANAGEMENT_TOKEN.

Public endpoints that remain unauthenticated:
  - /.well-known/ssf-configuration
  - /jwks.json
  - GET /apple-scim/status
  - GET /apple-scim/authorize
  - GET /apple-scim/callback
  - POST /webhook/authentik  (protected separately by HMAC)
"""

from __future__ import annotations

import hmac
import logging

from fastapi import Header, HTTPException

from app.config import settings

logger = logging.getLogger(__name__)


async def require_management_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: validate Bearer token using constant-time comparison.

    Returns None on success.
    Raises 401 when Authorization header is absent or malformed.
    Raises 403 when the token is present but incorrect.
    """
    if not authorization or not authorization.startswith("Bearer "):
        logger.warning("Management API request rejected: missing or malformed Authorization header")
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.removeprefix("Bearer ")
    if not hmac.compare_digest(
        token.encode("utf-8"),
        settings.ssf_management_token.encode("utf-8"),
    ):
        logger.warning("Management API request rejected: invalid token")
        raise HTTPException(status_code=403, detail="Forbidden")
