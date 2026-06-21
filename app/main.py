"""FastAPI application entry point and Apple SCIM background sync loop."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

import app.config as config
from app.config import configure_logging, settings
from app.crypto import ensure_keys
from app.database import init_db
from app.rate_limit import limiter
from app.routes import apple_scim, jwks, root, streams, verification, webhook, wellknown
from app.startup import quarantine_undecryptable_receiver_tokens, run_preflight_checks

configure_logging()
logger = logging.getLogger(__name__)

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a correlation ID to each request for logging and response headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
        token = request_id_var.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security-related HTTP response headers to all responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        content_type = response.headers.get("content-type", "")
        docs_html_paths = {"/docs", "/redoc", "/docs/oauth2-redirect"}
        if "text/html" in content_type and request.url.path not in docs_html_paths:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            )
        return response


async def _apple_scim_sync_loop() -> None:
    """Background task: sync users from Authentik to Apple every APPLE_SCIM_SYNC_INTERVAL seconds."""
    from app.alerts import send_alert
    from app.scim.apple import sync_users
    from app.scim.authentik import get_users
    from app.scim.token import get_valid_access_token

    logger.info("Apple SCIM: sync loop started interval=%ds", settings.apple_scim_sync_interval)
    while True:
        await asyncio.sleep(settings.apple_scim_sync_interval)
        logger.info("Apple SCIM: starting scheduled sync")
        try:
            token = await get_valid_access_token()
            if not token:
                logger.warning("Apple SCIM: skipping sync — no valid token; visit /apple-scim/authorize")
                await send_alert(
                    event="scim_no_valid_token",
                    message="Apple SCIM sync skipped — no valid token. Visit /apple-scim/authorize to re-authorize",
                )
                continue
            users = await get_users()
            if users is not None:
                await sync_users(token, users)
        except Exception:
            logger.exception("Apple SCIM: unhandled error in sync loop")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup preflight, initialize keys/DB, and manage background tasks."""
    run_preflight_checks()  # logs ✅/⚠️/❌ for each check; exits with 0 if any ❌
    ensure_keys()
    await init_db()
    quarantine_undecryptable_receiver_tokens()

    apple_scim_task: asyncio.Task | None = None
    if settings.apple_scim_enabled:
        logger.info("Apple SCIM sync enabled — background sync every %ds", settings.apple_scim_sync_interval)
        apple_scim_task = asyncio.create_task(_apple_scim_sync_loop())

    yield

    if apple_scim_task is not None:
        apple_scim_task.cancel()
        try:
            await apple_scim_task
        except asyncio.CancelledError:
            logger.info("Apple SCIM: sync loop stopped")


def create_app() -> FastAPI:
    """Build the FastAPI application (reads :data:`settings` at call time)."""
    cfg = config.settings
    openapi_enabled = cfg.ssf_enable_openapi
    docs_url = "/docs" if openapi_enabled else None
    redoc_url = "/redoc" if openapi_enabled else None
    openapi_url = "/openapi.json" if openapi_enabled else None

    application = FastAPI(
        root_path=cfg.ssf_root_path,
        title="SSF Transmitter",
        version=os.getenv("APP_VERSION", "dev"),
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # Starlette middleware is LIFO — register innermost first, outermost last.
    # RequestIDMiddleware wraps SlowAPIMiddleware so 429 responses still get X-Request-ID.
    application.add_middleware(SlowAPIMiddleware)
    application.add_middleware(RequestIDMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)
    application.include_router(root.router)
    application.include_router(wellknown.router)
    application.include_router(jwks.router)
    application.include_router(streams.router)
    application.include_router(verification.router)
    application.include_router(webhook.router)
    application.include_router(apple_scim.router)
    root.register_exception_handlers(application)
    return application


app = create_app()
