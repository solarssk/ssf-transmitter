import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import configure_logging, settings
from app.crypto import ensure_keys
from app.database import init_db
from app.routes import apple_scim, jwks, streams, webhook, wellknown

configure_logging()
logger = logging.getLogger(__name__)


async def _apple_scim_sync_loop() -> None:
    """Background task: sync users from Authentik to Apple every APPLE_SCIM_SYNC_INTERVAL seconds."""
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
                continue
            users = await get_users()
            if users is not None:
                await sync_users(token, users)
        except Exception:
            logger.exception("Apple SCIM: unhandled error in sync loop")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SSF Transmitter config=%s", settings.safe_log_dict())
    if settings.ssf_webhook_auth_mode == "unsigned":
        logger.warning(
            "⚠️  SSF_WEBHOOK_AUTH_MODE=unsigned — webhook requests are accepted WITHOUT authentication. "
            "This is UNSAFE. Use only in dev/lab environments protected by internal-only network."
        )
    ensure_keys()
    await init_db()

    apple_scim_task: asyncio.Task | None = None
    if settings.apple_scim_enabled:
        logger.info("Apple SCIM sync enabled — background sync every %ds", settings.apple_scim_sync_interval)
        apple_scim_task = asyncio.create_task(_apple_scim_sync_loop())
    else:
        logger.info(
            "Apple SCIM sync disabled "
            "(set APPLE_SCIM_CLIENT_ID, APPLE_SCIM_CLIENT_SECRET, AUTHENTIK_URL, AUTHENTIK_TOKEN to enable)"
        )

    yield

    if apple_scim_task is not None:
        apple_scim_task.cancel()
        try:
            await apple_scim_task
        except asyncio.CancelledError:
            logger.info("Apple SCIM: sync loop stopped")


app = FastAPI(root_path=settings.ssf_root_path, title="SSF Transmitter", lifespan=lifespan)
app.include_router(wellknown.router)
app.include_router(jwks.router)
app.include_router(streams.router)
app.include_router(webhook.router)
app.include_router(apple_scim.router)
