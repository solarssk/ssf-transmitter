from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Stream:
    stream_id: str
    aud: str
    endpoint_url: str
    endpoint_token: str
    events_requested: list[str]
    status: str
    created_at: int


def _row_to_stream(row: aiosqlite.Row) -> Stream:
    return Stream(
        stream_id=row["stream_id"],
        aud=row["aud"],
        endpoint_url=row["endpoint_url"],
        endpoint_token=row["endpoint_token"],
        events_requested=json.loads(row["events_requested"]),
        status=row["status"],
        created_at=row["created_at"],
    )


async def init_db() -> None:
    Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS streams (
              stream_id TEXT PRIMARY KEY,
              aud TEXT NOT NULL,
              endpoint_url TEXT NOT NULL,
              endpoint_token TEXT NOT NULL,
              events_requested TEXT NOT NULL,
              status TEXT DEFAULT 'enabled',
              created_at INTEGER NOT NULL
            )
            """
        )
        await db.commit()
    logger.info("Initialized SQLite database at %s", settings.database_path)


async def create_stream(payload: dict[str, Any]) -> Stream:
    delivery = payload.get("delivery") or {}
    endpoint_url = delivery.get("endpoint_url") or payload.get("endpoint_url")
    endpoint_token = delivery.get("endpoint_url_token") or payload.get("endpoint_token")
    aud = payload.get("aud") or payload.get("audience") or payload.get("receiver") or payload.get("iss")
    events_requested = payload.get("events_requested") or payload.get("events_supported") or []

    if not endpoint_url:
        raise ValueError("Missing delivery.endpoint_url")
    if not endpoint_token:
        raise ValueError("Missing delivery.endpoint_url_token")
    if not aud:
        raise ValueError("Missing aud")
    if not isinstance(events_requested, list):
        raise ValueError("events_requested must be a list when provided")

    stream = Stream(
        stream_id=payload.get("stream_id") or str(uuid.uuid4()),
        aud=aud,
        endpoint_url=endpoint_url,
        endpoint_token=endpoint_token,
        events_requested=events_requested,
        status=payload.get("status", "enabled"),
        created_at=int(time.time()),
    )

    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute("DELETE FROM streams")
        await db.execute(
            """
            INSERT OR REPLACE INTO streams
            (stream_id, aud, endpoint_url, endpoint_token, events_requested, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stream.stream_id,
                stream.aud,
                stream.endpoint_url,
                stream.endpoint_token,
                json.dumps(stream.events_requested),
                stream.status,
                stream.created_at,
            ),
        )
        await db.commit()

    logger.info("Created SSF stream stream_id=%s aud=%s status=%s", stream.stream_id, stream.aud, stream.status)
    return stream


async def list_streams() -> list[Stream]:
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM streams ORDER BY created_at DESC")
        rows = await cursor.fetchall()
    return [_row_to_stream(row) for row in rows]


async def get_first_stream() -> Stream | None:
    streams = await list_streams()
    return streams[0] if streams else None


async def update_stream(payload: dict[str, Any]) -> Stream | None:
    stream = await get_first_stream()
    if not stream:
        return None

    delivery = payload.get("delivery") or {}
    endpoint_url = delivery.get("endpoint_url") or payload.get("endpoint_url") or stream.endpoint_url
    endpoint_token = delivery.get("endpoint_url_token") or payload.get("endpoint_token") or stream.endpoint_token
    events_requested = payload.get("events_requested", stream.events_requested)
    status = payload.get("status", stream.status)
    aud = payload.get("aud") or payload.get("audience") or payload.get("receiver") or stream.aud

    if not isinstance(events_requested, list):
        raise ValueError("events_requested must be a list when provided")

    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute(
            """
            UPDATE streams
            SET aud = ?, endpoint_url = ?, endpoint_token = ?, events_requested = ?, status = ?
            WHERE stream_id = ?
            """,
            (aud, endpoint_url, endpoint_token, json.dumps(events_requested), status, stream.stream_id),
        )
        await db.commit()

    updated = Stream(stream.stream_id, aud, endpoint_url, endpoint_token, events_requested, status, stream.created_at)
    logger.info("Updated SSF stream stream_id=%s aud=%s status=%s", updated.stream_id, updated.aud, updated.status)
    return updated


async def delete_stream() -> bool:
    stream = await get_first_stream()
    if not stream:
        return False
    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute("DELETE FROM streams WHERE stream_id = ?", (stream.stream_id,))
        await db.commit()
    logger.info("Deleted SSF stream stream_id=%s aud=%s", stream.stream_id, stream.aud)
    return True
