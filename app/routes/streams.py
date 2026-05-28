import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Response

import uuid

from app.database import create_stream, delete_stream, get_first_stream, update_stream
from app.events.pusher import push_verification_set

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ssf")


def _stream_response(stream) -> dict[str, Any]:
    return {
        "stream_id": stream.stream_id,
        "aud": stream.aud,
        "delivery": {
            "method": "https://schemas.openid.net/secevent/risc/delivery-method/push",
            "endpoint_url": stream.endpoint_url,
        },
        "events_requested": stream.events_requested,
        "status": stream.status,
        "created_at": stream.created_at,
    }


@router.post("/streams", status_code=201)
async def create_stream_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
    delivery = payload.get("delivery") or {}
    logger.info(
        "Stream create request payload_keys=%s delivery_keys=%s",
        sorted(payload.keys()),
        sorted(delivery.keys()),
    )
    logger.debug("Stream create payload=%s", payload)
    try:
        stream = await create_stream(payload)
    except ValueError as exc:
        _REDACTED = "[redacted]"
        safe_delivery = {
            k: (_REDACTED if k in {"endpoint_url_token", "authorization_header"} else v)
            for k, v in delivery.items()
        }
        logger.warning(
            "Stream create rejected reason=%s payload_keys=%s delivery_keys=%s delivery=%s",
            exc,
            sorted(payload.keys()),
            sorted(delivery.keys()),
            safe_delivery,
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    verification_state = str(uuid.uuid4())
    pushed = await push_verification_set(stream, state=verification_state)
    if not pushed:
        logger.warning(
            "Verification SET delivery failed stream_id=%s aud=%s",
            stream.stream_id,
            stream.aud,
        )
    return _stream_response(stream)


@router.get("/streams")
async def get_stream_endpoint() -> dict[str, Any]:
    stream = await get_first_stream()
    if not stream:
        raise HTTPException(status_code=404, detail="No stream configured")
    return _stream_response(stream)


@router.patch("/streams")
async def patch_stream_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        stream = await update_stream(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not stream:
        raise HTTPException(status_code=404, detail="No stream configured")
    return _stream_response(stream)


@router.delete("/streams", status_code=204)
async def delete_stream_endpoint() -> Response:
    await delete_stream()
    return Response(status_code=204)


@router.post("/streams/subjects:add")
async def add_subject(payload: dict[str, Any]) -> dict[str, str]:
    logger.info("Registered SSF subject payload_keys=%s", sorted(payload.keys()))
    return {"status": "ok"}


@router.post("/streams/subjects:remove")
async def remove_subject(payload: dict[str, Any]) -> dict[str, str]:
    logger.info("Removed SSF subject payload_keys=%s", sorted(payload.keys()))
    return {"status": "ok"}


@router.get("/status")
async def stream_status() -> dict[str, Any]:
    stream = await get_first_stream()
    if not stream:
        return {"status": "disabled", "reason": "no_stream"}
    return {
        "status": stream.status,
        "stream_id": stream.stream_id,
        "aud": stream.aud,
        "events_requested": stream.events_requested,
    }
