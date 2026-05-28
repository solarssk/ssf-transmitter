from __future__ import annotations

import json
import logging
import os
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
    """Convert a database row to a Stream dataclass."""
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
    """Create all database tables if they do not already exist.

    Security note: receiver tokens (bearer tokens for push endpoints) are stored
    in plaintext inside this SQLite database.  Protect the /app/data volume:
    restrict container host-path mounts to root-only, use encrypted storage at
    the volume level if your threat model requires it, and never expose the data
    directory via network shares.
    """
    db_path = Path(settings.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    logger.warning(
        "Receiver tokens are stored in plaintext in SQLite at %s — "
        "ensure the %s volume is protected (host path restricted to root, "
        "encrypted volume if required by your threat model).",
        settings.database_path,
        str(db_path.parent),
    )
    # Pre-create the file with 0600 permissions before SQLite opens it.
    # Using os.open with O_CREAT|O_WRONLY and mode=0o600 sets the permission
    # atomically, closing the TOCTOU window that exists when creating first
    # and chmod-ing afterwards.  The fd is closed immediately; SQLite then
    # opens the already-existing file and inherits its permissions.
    if not db_path.exists():
        fd = os.open(str(db_path), os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    else:
        # File already exists (restart) — enforce permissions in case they
        # were changed by a previous deployment or volume remount.
        try:
            db_path.chmod(0o600)
        except OSError as exc:
            logger.warning("Could not set 0600 permissions on DB file %s: %s", settings.database_path, exc)
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
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS apple_scim_tokens (
              id            INTEGER PRIMARY KEY,
              access_token  TEXT NOT NULL,
              refresh_token TEXT,
              expires_at    INTEGER NOT NULL,
              updated_at    INTEGER NOT NULL
            )
            """
        )
        await db.commit()
    logger.info("Initialized SQLite database at %s", settings.database_path)


async def create_stream(payload: dict[str, Any]) -> Stream:
    """Create a new SSF stream from a registration payload, replacing any existing stream."""
    delivery = payload.get("delivery") or {}
    endpoint_url = delivery.get("endpoint_url") or payload.get("endpoint_url")
    auth_header = delivery.get("authorization_header", "")
    endpoint_token = (
        delivery.get("endpoint_url_token")
        or payload.get("endpoint_token")
        or (auth_header.removeprefix("Bearer ") if auth_header else None)
        or ""
    )
    aud = payload.get("aud")
    events_requested = payload.get("events_requested") or []

    if not endpoint_url:
        raise ValueError("Missing delivery.endpoint_url")
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
    """Return all configured streams ordered by creation time."""
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM streams ORDER BY created_at DESC")
        rows = await cursor.fetchall()
    return [_row_to_stream(row) for row in rows]


async def get_first_stream() -> Stream | None:
    """Return the most recently created stream, or None if no stream is configured."""
    streams = await list_streams()
    return streams[0] if streams else None


async def update_stream(payload: dict[str, Any]) -> Stream | None:
    """Update fields on the existing stream; returns None if no stream exists."""
    stream = await get_first_stream()
    if not stream:
        return None

    delivery = payload.get("delivery") or {}
    endpoint_url = delivery.get("endpoint_url") or payload.get("endpoint_url") or stream.endpoint_url
    auth_header = delivery.get("authorization_header", "")
    endpoint_token = (
        delivery.get("endpoint_url_token")
        or payload.get("endpoint_token")
        or (auth_header.removeprefix("Bearer ") if auth_header else None)
        or stream.endpoint_token
    )
    events_requested = payload.get("events_requested", stream.events_requested)
    status = payload.get("status", stream.status)
    aud = payload.get("aud") or stream.aud

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
    """Delete the current stream; returns True if a stream was deleted, False if none existed."""
    stream = await get_first_stream()
    if not stream:
        return False
    return await delete_stream_by_id(stream.stream_id)


async def delete_stream_by_id(stream_id: str) -> bool:
    """Delete a specific stream by ID; returns True if deleted, False if not found."""
    async with aiosqlite.connect(settings.database_path) as db:
        cursor = await db.execute("DELETE FROM streams WHERE stream_id = ?", (stream_id,))
        await db.commit()
        deleted = cursor.rowcount > 0
    if deleted:
        logger.info("Deleted SSF stream stream_id=%s", stream_id)
    return deleted
