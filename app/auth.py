"""FastAPI dependency for management API bearer token authentication.

All SSF management endpoints (/ssf/streams, /ssf/status, /apple-scim/sync)
require a Bearer token matching SSF_MANAGEMENT_TOKEN.

Public endpoints that remain unauthenticated:
  - /.well-known/ssf-configuration
  - /jwks.json
  - GET /apple-scim/authorize  (OAuth flow — admin browser)
  - GET /apple-scim/callback   (OAuth redirect from Apple — CSRF protected via state)
  - POST /webhook/authentik  (protected separately by bearer/HMAC)
"""

from __future__ import annotations

import hmac
import logging
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request

from app.config import settings
from app.rate_limit import limiter

logger = logging.getLogger(__name__)

_MANAGEMENT_AUTH_FAILURE_LIMIT = 10
_MANAGEMENT_AUTH_FAILURE_WINDOW_SECONDS = 60.0
_management_auth_failures: dict[str, deque[float]] = defaultdict(
    lambda: deque(maxlen=_MANAGEMENT_AUTH_FAILURE_LIMIT + 1)
)
# Guards _management_auth_failures: a plain threading.Lock (not asyncio.Lock)
# because require_management_auth being `async def` keeps this on the single
# event-loop thread in production, but the lock also makes this function
# safe to call from any real OS thread — defense in depth, not a substitute
# for staying async (see the comment on require_management_auth below).
_management_auth_failures_lock = threading.Lock()


def _client_key(request: Request) -> str:
    """Return a rate-limit key for management auth failures."""
    if request.client and request.client.host:
        return request.client.host
    return "unknown-client"


def _record_management_auth_failure(request: Request) -> None:
    """Rate-limit failed management auth attempts before endpoint handlers run."""
    if not limiter.enabled:
        return

    now = time.monotonic()
    client_key = _client_key(request)
    with _management_auth_failures_lock:
        attempts = _management_auth_failures[client_key]
        while attempts and now - attempts[0] >= _MANAGEMENT_AUTH_FAILURE_WINDOW_SECONDS:
            attempts.popleft()
        if not attempts:
            _management_auth_failures.pop(client_key, None)
            attempts = _management_auth_failures[client_key]
        attempts.append(now)
        exceeded = len(attempts) > _MANAGEMENT_AUTH_FAILURE_LIMIT

    if exceeded:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


async def require_management_auth(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    """FastAPI dependency: validate Bearer token using constant-time comparison.

    Returns None on success.
    Raises 401 when Authorization header is absent or malformed.
    Raises 403 when the token is present but incorrect.

    Deliberately `async def` despite having no internal `await`: FastAPI
    dispatches a plain sync dependency to a worker thread via
    `run_in_threadpool`, so concurrent failed-auth requests from the same
    client would run this function — and mutate the shared
    `_management_auth_failures` state — on different OS threads at once.
    Staying `async def` keeps every invocation on the single event-loop
    thread instead, which is the real fix; the lock in
    `_record_management_auth_failure` is defense in depth on top of that,
    not a substitute for it. Do not "clean up" this async keyword.
    """
    if not authorization or not authorization.startswith("Bearer "):
        _record_management_auth_failure(request)
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
        _record_management_auth_failure(request)
        logger.warning("Management API request rejected: invalid token")
        raise HTTPException(status_code=403, detail="Forbidden")
