"""Durable, encrypted queue for outbound signed SET deliveries."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import suppress
from typing import Any

from app.crypto import EncryptedDataError, sign_set
from app.database import (
    OutboxItem,
    Stream,
    block_outbox_item,
    cancel_outbox_item,
    complete_outbox_item,
    decrypt_outbox_payload,
    enqueue_outbox,
    get_due_outbox,
    get_due_outbox_item,
    get_stream_by_id,
    retry_outbox_item,
    stream_operation_lock,
)
from app.events.mapper import MappedEvent
from app.events.pusher import push_signed_set

logger = logging.getLogger(__name__)

_RETRY_BASE_SECONDS = 5
_RETRY_MAX_SECONDS = 60 * 60
_PAUSED_RECHECK_SECONDS = 30
_DELIVERY_DEADLINE_SECONDS = 30


async def enqueue_events(streams: list[Stream], events: list[MappedEvent], email: str) -> int:
    """Sign matching events and durably enqueue them as one database operation."""
    deliveries: list[tuple[Stream, dict[str, Any]]] = []
    for stream in streams:
        if stream.status != "enabled":
            continue
        for event in events:
            if stream.events_requested and event.uri not in stream.events_requested:
                continue
            token = sign_set(
                event_uri=event.uri,
                audience=stream.aud,
                email=email,
                event_payload=event.payload,
                txn=event.txn,
            )
            deliveries.append(
                (
                    stream,
                    {
                        "aud": stream.aud,
                        "endpoint_url": stream.endpoint_url,
                        "endpoint_token": stream.endpoint_token,
                        "events_requested": stream.events_requested,
                        "event_uri": event.uri,
                        "token": token,
                    },
                )
            )
    return await enqueue_outbox(deliveries)


def _payload_matches_stream(payload: dict[str, Any], stream: Stream) -> bool:
    """Ensure queued data is still addressed to the stream's current configuration."""
    return (
        payload.get("aud") == stream.aud
        and payload.get("endpoint_url") == stream.endpoint_url
        and payload.get("endpoint_token") == stream.endpoint_token
        and payload.get("events_requested") == stream.events_requested
    )


def _valid_payload(payload: dict[str, Any]) -> bool:
    return (
        isinstance(payload.get("aud"), str)
        and isinstance(payload.get("endpoint_url"), str)
        and isinstance(payload.get("endpoint_token"), str)
        and isinstance(payload.get("events_requested"), list)
        and all(isinstance(uri, str) for uri in payload["events_requested"])
        and isinstance(payload.get("event_uri"), str)
        and isinstance(payload.get("token"), str)
    )


async def _retry(item: OutboxItem, reason: str) -> None:
    attempts = item.attempts + 1
    delay = min(_RETRY_MAX_SECONDS, _RETRY_BASE_SECONDS * 2 ** min(attempts - 1, 10))
    await retry_outbox_item(item.id, attempts, int(time.time()) + delay, reason)
    logger.warning(
        "Queued SET delivery will retry item_id=%s stream_id=%s attempts=%d delay_seconds=%d reason=%s",
        item.id,
        item.stream_id,
        attempts,
        delay,
        reason,
    )


async def _deliver_item(item: OutboxItem) -> None:
    try:
        payload = await decrypt_outbox_payload(item)
    except EncryptedDataError:
        await block_outbox_item(item.id, "payload_decryption_failed")
        logger.exception("Blocked queued SET with unreadable payload item_id=%s stream_id=%s", item.id, item.stream_id)
        return

    if not _valid_payload(payload):
        await block_outbox_item(item.id, "payload_invalid")
        logger.error("Blocked queued SET with invalid payload item_id=%s stream_id=%s", item.id, item.stream_id)
        return

    stream = await get_stream_by_id(item.stream_id)
    if stream is None or not _payload_matches_stream(payload, stream):
        await cancel_outbox_item(item.id)
        logger.warning("Cancelled queued SET for changed stream item_id=%s stream_id=%s", item.id, item.stream_id)
        return
    if stream.status != "enabled":
        await retry_outbox_item(
            item.id,
            item.attempts,
            int(time.time()) + _PAUSED_RECHECK_SECONDS,
            "stream_paused",
        )
        return

    try:
        delivered = await asyncio.wait_for(
            push_signed_set(stream, payload["token"], payload["event_uri"]),
            timeout=_DELIVERY_DEADLINE_SECONDS,
        )
    except TimeoutError:
        logger.warning("Queued SET delivery timed out item_id=%s stream_id=%s", item.id, item.stream_id)
        await _retry(item, "delivery_timeout")
        return
    except Exception:
        logger.exception("Unexpected queued SET delivery error item_id=%s stream_id=%s", item.id, item.stream_id)
        await _retry(item, "delivery_error")
        return

    if delivered:
        await complete_outbox_item(item.id)
    else:
        await _retry(item, "delivery_failed")


async def deliver_pending(*, stop: asyncio.Event | None = None) -> int:
    """Attempt all currently due deliveries; return the number attempted."""
    items = await get_due_outbox()
    attempted = 0
    for item in items:
        if stop is not None and stop.is_set():
            break
        async with stream_operation_lock():
            if stop is not None and stop.is_set():
                break
            current = await get_due_outbox_item(item.id)
            if current is None:
                continue
            await _deliver_item(current)
            attempted += 1
    return attempted


async def delivery_loop(stop: asyncio.Event, poll_interval_seconds: int = 5) -> None:
    """Continuously resume queued deliveries after startup and retry failures."""
    logger.info("SSF delivery outbox worker started poll_interval_seconds=%d", poll_interval_seconds)
    while not stop.is_set():
        try:
            await deliver_pending(stop=stop)
        except Exception:
            logger.exception("SSF delivery outbox worker encountered an unexpected error")
        if not stop.is_set():
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_interval_seconds)
