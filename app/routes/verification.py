"""Receiver-initiated SSF verification SET endpoint."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, model_validator

from app.auth import require_management_auth
from app.database import get_first_stream
from app.events.pusher import push_verification_set

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ssf", dependencies=[Depends(require_management_auth)])


class VerificationRequest(BaseModel):
    """Optional body for POST /ssf/verification."""

    state: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _coerce_string(cls, value: object) -> object:
        """Accept a bare string body as {"state": value} for API convenience."""
        if isinstance(value, str):
            return {"state": value}
        return value


@router.post("/verification", status_code=202)
async def trigger_verification(request: VerificationRequest | None = None) -> Response:
    """Trigger a receiver-initiated verification SET.

    Pushes a verification SET to the current stream's endpoint. If ``state`` is
    provided it is included in the SET so the receiver can correlate the response.

    Returns 202 on success, 404 if no stream is configured, 502 if the receiver
    rejects the verification SET.
    """
    stream = await get_first_stream()
    if not stream:
        raise HTTPException(status_code=404, detail="No stream configured")

    state = request.state if request else None
    pushed = await push_verification_set(stream, state=state)

    if not pushed:
        logger.warning(
            "Verification SET delivery failed stream_id=%s aud=%s",
            stream.stream_id,
            stream.aud,
        )
        raise HTTPException(
            status_code=502,
            detail="Verification SET delivery failed",
        )

    logger.info("Verification SET delivered stream_id=%s aud=%s", stream.stream_id, stream.aud)
    return Response(status_code=202)
