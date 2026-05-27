import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import configure_logging, settings
from app.crypto import ensure_keys
from app.database import init_db
from app.routes import jwks, streams, webhook, wellknown

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SSF Transmitter config=%s", settings.safe_log_dict())
    ensure_keys()
    await init_db()
    yield


app = FastAPI(root_path=settings.ssf_root_path, title="SSF Transmitter", lifespan=lifespan)
app.include_router(wellknown.router)
app.include_router(jwks.router)
app.include_router(streams.router)
app.include_router(webhook.router)
