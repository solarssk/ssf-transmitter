"""SSF stream management API (create, read, update, delete)."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.auth import require_management_auth
from app.config import settings
from app.database import create_stream, delete_stream, delete_stream_by_id, get_first_stream, update_stream
from app.events.pusher import push_verification_set
from app.models import SUPPORTED_EVENT_URIS, StreamCreateRequest, StreamPatchRequest
from app.rate_limit import limiter
from app.security.url_validation import validate_receiver_endpoint_url

_EVENTS_SUPPORTED = sorted(SUPPORTED_EVENT_URIS)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ssf", dependencies=[Depends(require_management_auth)])


def _stream_response(stream) -> dict[str, Any]:
    """Serialize a Stream row into the SSF stream management response shape."""
    events_delivered = (
        [e for e in stream.events_requested if e in _EVENTS_SUPPORTED]
        if stream.events_requested is not None
        else _EVENTS_SUPPORTED
    )
    return {
        "iss": settings.ssf_issuer,
        "stream_id": stream.stream_id,
        "aud": stream.aud,
        "delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": stream.endpoint_url,
        },
        "events_supported": _EVENTS_SUPPORTED,
        "events_requested": stream.events_requested,
        "events_delivered": events_delivered,
        "status": stream.status,
        "stream_model": "single-stream",
        "created_at": stream.created_at,
    }


async def _get_stream_or_404(stream_id: str | None = None):
    """Return the current stream, optionally asserting the provided ID matches it."""
    stream = await get_first_stream()
    if not stream:
        raise HTTPException(status_code=404, detail="No stream configured")
    if stream_id is not None and stream.stream_id != stream_id:
        raise HTTPException(status_code=404, detail="Stream not found")
    return stream


@router.post("/streams", status_code=201)
@limiter.limit("10/minute")
async def create_stream_endpoint(request: Request, body: StreamCreateRequest) -> dict[str, Any]:
    """Create a new SSF stream and confirm delivery by pushing a verification SET."""
    endpoint_url = body.delivery.endpoint_url
    logger.info(
        "Stream create request aud=%s events_requested=%s",
        body.aud,
        body.events_requested,
    )
    try:
        validate_receiver_endpoint_url(
            endpoint_url,
            allowed_hosts=settings.ssf_allowed_receiver_hosts or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid endpoint_url: {exc}") from exc

    # Build a normalised dict for the database layer
    payload: dict[str, Any] = {
        "aud": body.aud,
        "delivery": {
            "endpoint_url": endpoint_url,
            "endpoint_url_token": body.delivery.endpoint_url_token or "",
            "authorization_header": body.delivery.authorization_header or "",
        },
        "events_requested": body.events_requested,
        "status": body.status.value,
    }

    try:
        stream = await create_stream(payload)
    except ValueError as exc:
        logger.warning("Stream create rejected reason=%s aud=%s", exc, body.aud)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    pushed = await push_verification_set(stream)
    if not pushed:
        logger.warning(
            "Verification SET delivery failed; rolling back stream_id=%s aud=%s",
            stream.stream_id,
            stream.aud,
        )
        await delete_stream_by_id(stream.stream_id)
        raise HTTPException(
            status_code=502,
            detail="Verification SET delivery failed; stream registration was not confirmed.",
        )

    return _stream_response(stream)


@router.get("/streams")
async def get_stream_endpoint() -> dict[str, Any]:
    """Return the current SSF stream configuration."""
    return _stream_response(await _get_stream_or_404())


@router.get("/streams/{stream_id}")
async def get_stream_by_id_endpoint(stream_id: str) -> dict[str, Any]:
    """Return a stream by ID."""
    return _stream_response(await _get_stream_or_404(stream_id))


async def _patch_stream_body(body: StreamPatchRequest) -> dict[str, Any]:
    """Apply a validated stream patch body without route-level side effects."""
    # Validate endpoint_url if delivery block is included in the patch
    if body.delivery is not None:
        try:
            validate_receiver_endpoint_url(
                body.delivery.endpoint_url,
                allowed_hosts=settings.ssf_allowed_receiver_hosts or None,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid endpoint_url: {exc}") from exc

    # Build a sparse dict — only include fields that were explicitly set
    patch: dict[str, Any] = {}
    if body.aud is not None:
        patch["aud"] = body.aud
    if body.status is not None:
        patch["status"] = body.status.value
    if body.events_requested is not None:
        patch["events_requested"] = body.events_requested
    if body.delivery is not None:
        delivery_patch = {"endpoint_url": body.delivery.endpoint_url}
        if body.delivery.endpoint_url_token is not None:
            delivery_patch["endpoint_url_token"] = body.delivery.endpoint_url_token
        if body.delivery.authorization_header is not None:
            delivery_patch["authorization_header"] = body.delivery.authorization_header
        patch["delivery"] = delivery_patch

    try:
        stream = await update_stream(patch)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not stream:
        raise HTTPException(status_code=404, detail="No stream configured")
    return _stream_response(stream)


@router.patch("/streams")
@limiter.limit("20/minute")
async def patch_stream_endpoint(request: Request, body: StreamPatchRequest) -> dict[str, Any]:
    """Update the current SSF stream configuration."""
    return await _patch_stream_body(body)


@router.patch("/streams/{stream_id}")
@limiter.limit("20/minute")
async def patch_stream_by_id_endpoint(
    stream_id: str, request: Request, body: StreamPatchRequest
) -> dict[str, Any]:
    """Update a stream by ID."""
    await _get_stream_or_404(stream_id)
    return await _patch_stream_body(body)


@router.delete("/streams", status_code=204)
async def delete_stream_endpoint() -> Response:
    """Delete the current SSF stream."""
    await delete_stream()
    return Response(status_code=204)


@router.delete("/streams/{stream_id}", status_code=204)
async def delete_stream_by_id_endpoint(stream_id: str) -> Response:
    """Delete a stream by ID."""
    deleted = await delete_stream_by_id(stream_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Stream not found")
    return Response(status_code=204)


@router.post("/streams/subjects:add")
async def add_subject(payload: dict[str, Any]) -> dict[str, str]:
    """Register a subject on the current SSF stream."""
    logger.info("Registered SSF subject payload_keys=%s", sorted(payload.keys()))
    return {"status": "ok"}


@router.post("/streams/subjects:remove")
async def remove_subject(payload: dict[str, Any]) -> dict[str, str]:
    """Remove a subject from the current SSF stream."""
    logger.info("Removed SSF subject payload_keys=%s", sorted(payload.keys()))
    return {"status": "ok"}


@router.get("/status")
async def stream_status() -> dict[str, Any]:
    """Return the current SSF stream status."""
    stream = await get_first_stream()
    if not stream:
        return {"status": "disabled", "reason": "no_stream"}
    return {
        "status": stream.status,
        "stream_id": stream.stream_id,
        "aud": stream.aud,
        "events_requested": stream.events_requested,
    }


@router.get("/streams/{stream_id}/status")
async def stream_status_by_id(stream_id: str) -> dict[str, Any]:
    """Return the current status for a stream by ID."""
    stream = await _get_stream_or_404(stream_id)
    return {
        "status": stream.status,
        "stream_id": stream.stream_id,
        "aud": stream.aud,
        "events_requested": stream.events_requested,
    }


@router.post("/streams/{stream_id}/verify", status_code=202)
async def verify_stream_by_id(stream_id: str) -> Response:
    """Push a verification SET for a stream by ID."""
    stream = await _get_stream_or_404(stream_id)
    pushed = await push_verification_set(stream)
    if not pushed:
        raise HTTPException(status_code=502, detail="Verification SET delivery failed")
    return Response(status_code=202)
