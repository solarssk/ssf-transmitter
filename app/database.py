"""SQLite persistence for SSF streams and Apple SCIM OAuth tokens."""

from __future__ import annotations

import asyncio
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
from app.crypto import (
    EncryptedDataError,
    TokenDecryptionError,
    decrypt_sensitive_data,
    decrypt_token,
    encrypt_sensitive_data,
    encrypt_token,
)
from app.security.log_sanitize import sanitize_for_log

logger = logging.getLogger(__name__)

MAX_OUTBOX_ITEMS = 10_000

# Serializes stream mutations with each other and with outbox delivery, so
# a completed pause, replacement, or queue discard cannot send stale items.
# This relies on the single Uvicorn worker configured in the Dockerfile.
_stream_write_lock: asyncio.Lock | None = None
_stream_write_lock_loop: asyncio.AbstractEventLoop | None = None


def stream_operation_lock() -> asyncio.Lock:
    """Return the process-wide stream operation lock, recreating it if the
    running event loop has changed since it was created.

    In production there's exactly one uvicorn event loop for the process's
    entire lifetime, so this runs once and the lock is reused forever. A
    module-level `asyncio.Lock()` created eagerly at import time would
    instead bind to whichever loop first acquires it and then raise
    "bound to a different event loop" the moment a *different* loop tries
    to use it — which is exactly what happens under a test suite that
    creates a fresh event loop per test function. A lock bound to a dead
    loop isn't protecting anything real across that boundary anyway, so
    recreating it here is safe.
    """
    global _stream_write_lock, _stream_write_lock_loop
    loop = asyncio.get_running_loop()
    if _stream_write_lock is None or _stream_write_lock_loop is not loop:
        _stream_write_lock = asyncio.Lock()
        _stream_write_lock_loop = loop
    return _stream_write_lock


@dataclass(frozen=True)
class Stream:
    """An active or paused SSF push stream stored in SQLite."""

    stream_id: str
    aud: str
    endpoint_url: str
    endpoint_token: str
    events_requested: list[str]
    status: str
    created_at: int


@dataclass(frozen=True)
class OutboxItem:
    """A pending signed SET delivery encrypted at rest."""

    id: int
    stream_id: str
    payload: str
    created_at: int
    attempts: int


class StreamChangedError(Exception):
    """Raised when a stream changes while a webhook is being queued."""


class OutboxFullError(Exception):
    """Raised when the durable delivery queue has reached its storage limit."""


def _row_to_stream(row: aiosqlite.Row) -> Stream:
    """Convert a database row to a Stream dataclass."""
    try:
        endpoint_token = decrypt_token(row["endpoint_token"])
    except TokenDecryptionError:
        logger.warning(
            "Stream %s has an undecryptable receiver token; returning empty runtime token",
            row["stream_id"],
        )
        endpoint_token = ""
    return Stream(
        stream_id=row["stream_id"],
        aud=row["aud"],
        endpoint_url=row["endpoint_url"],
        endpoint_token=endpoint_token,
        events_requested=json.loads(row["events_requested"]),
        status=row["status"],
        created_at=row["created_at"],
    )


def _replacement_endpoint_token(payload: dict[str, Any]) -> str | None:
    """Return a newly supplied endpoint token, or None when the patch preserves it."""
    delivery = payload.get("delivery") or {}
    if "endpoint_url_token" in delivery:
        return delivery["endpoint_url_token"]
    if "endpoint_token" in payload:
        return payload["endpoint_token"]
    if "authorization_header" in delivery:
        auth_header = delivery["authorization_header"]
        if auth_header:
            return auth_header.removeprefix("Bearer ")
        return ""
    return None


def _receiver_replacement_is_missing(token: str | None) -> bool:
    """Return True when a patch does not supply a usable replacement receiver token."""
    return token is None or not str(token).strip()


def _stored_token_is_undecryptable(stored_token: str, runtime_token: str) -> bool:
    """Return True when SQLite holds ciphertext but runtime delivery token is unavailable."""
    return bool(stored_token) and not runtime_token


def _create_file_exclusive(path: str, mode: int) -> None:
    """Create *path* with *mode* if it doesn't exist; raises FileExistsError otherwise.

    O_CREAT | O_WRONLY | O_EXCL is atomic: it either creates the file
    exclusively with the given mode, or raises FileExistsError if it already
    exists — eliminating the TOCTOU race that a preceding exists() check
    would introduce.
    """
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, mode)
    os.close(fd)


async def init_db() -> None:
    """Create all database tables if they do not already exist.

    Security note: receiver tokens and signed SET payloads are encrypted at
    rest (Fernet) in SQLite. Protect the /app/data volume: restrict container
    host-path mounts to root-only, use encrypted storage at the volume level
    if your threat model requires it, and never expose it via network shares.
    """
    db_path = Path(settings.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info(
        "Receiver endpoint tokens are encrypted at rest in SQLite at %s — "
        "protect the %s volume (host path restricted to root, encrypted volume "
        "if required by your threat model).",
        settings.database_path,
        str(db_path.parent),
    )
    # Pre-create the DB file with 0600 permissions before SQLite opens it.
    try:
        await asyncio.to_thread(_create_file_exclusive, str(db_path), 0o600)
    except FileExistsError:
        # File already exists (restart) — enforce permissions in case they
        # drifted due to a previous deployment or volume remount.
        try:
            await asyncio.to_thread(db_path.chmod, 0o600)
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
        # Runtime settings — key/value store for configuration that can be
        # changed without a container restart.  Reserved for the v1.x admin UI.
        # Values are JSON-encoded so they can hold strings, booleans, lists, etc.
        # Keys follow the pattern: "<module>.<setting>" e.g. "scim.name_split_mode"
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_settings (
              key        TEXT PRIMARY KEY,
              value      TEXT NOT NULL,
              updated_at INTEGER NOT NULL
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS set_outbox (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              stream_id TEXT NOT NULL,
              payload TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0,
              next_attempt_at INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              last_error TEXT
            )
            """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_set_outbox_due ON set_outbox(status, next_attempt_at, created_at)"
        )
        await db.commit()
    logger.info("Initialized SQLite database at %s", settings.database_path)


def prepare_stream(payload: dict[str, Any]) -> Stream:
    """Build a validated stream candidate without modifying the existing stream."""
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

    return Stream(
        stream_id=payload.get("stream_id") or str(uuid.uuid4()),
        aud=aud,
        endpoint_url=endpoint_url,
        endpoint_token=endpoint_token,
        events_requested=events_requested,
        status=payload.get("status", "enabled"),
        created_at=int(time.time()),
    )


async def save_stream(stream: Stream) -> None:
    """Atomically replace the stored stream with an already prepared candidate."""
    async with stream_operation_lock(), aiosqlite.connect(settings.database_path) as db:
        await db.execute("BEGIN IMMEDIATE")
        await db.execute("DELETE FROM set_outbox WHERE status = 'pending'")
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
                encrypt_token(stream.endpoint_token),
                json.dumps(stream.events_requested),
                stream.status,
                stream.created_at,
            ),
        )
        await db.commit()

    logger.info(
        "Created SSF stream stream_id=%s aud=%s status=%s",
        sanitize_for_log(stream.stream_id),
        sanitize_for_log(stream.aud),
        stream.status,
    )


async def create_stream(payload: dict[str, Any]) -> Stream:
    """Create a new SSF stream from a registration payload, replacing any existing stream."""
    stream = prepare_stream(payload)
    await save_stream(stream)
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


async def get_stream_by_id(stream_id: str) -> Stream | None:
    """Return a stream by ID, or None if it no longer exists."""
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM streams WHERE stream_id = ?", (stream_id,))
        row = await cursor.fetchone()
    return _row_to_stream(row) if row else None


async def update_stream(payload: dict[str, Any]) -> Stream | None:
    """Update fields on the existing stream; returns None if no stream exists."""
    async with stream_operation_lock(), aiosqlite.connect(settings.database_path) as db:
        await db.execute("BEGIN IMMEDIATE")
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM streams ORDER BY created_at DESC LIMIT 1")
        row = await cursor.fetchone()
        if row is None:
            return None

        stream = _row_to_stream(row)
        delivery = payload.get("delivery") or {}
        endpoint_url = delivery.get("endpoint_url") or payload.get("endpoint_url") or stream.endpoint_url
        endpoint_token = _replacement_endpoint_token(payload)
        stored_endpoint_token = encrypt_token(endpoint_token) if endpoint_token is not None else row["endpoint_token"]
        runtime_endpoint_token = endpoint_token if endpoint_token is not None else stream.endpoint_token
        events_requested = payload.get("events_requested", stream.events_requested)
        status = payload.get("status", stream.status)
        aud = payload.get("aud") or stream.aud

        if not isinstance(events_requested, list):
            raise ValueError("events_requested must be a list when provided")

        if (
            status == "enabled"
            and _stored_token_is_undecryptable(row["endpoint_token"], stream.endpoint_token)
            and _receiver_replacement_is_missing(endpoint_token)
        ):
            raise ValueError(
                "Receiver endpoint token cannot be decrypted — supply delivery.endpoint_url_token before enabling"
            )

        delivery_configuration_changed = (
            aud != stream.aud
            or endpoint_url != stream.endpoint_url
            or runtime_endpoint_token != stream.endpoint_token
            or events_requested != stream.events_requested
        )
        if delivery_configuration_changed:
            await db.execute("DELETE FROM set_outbox WHERE stream_id = ? AND status = 'pending'", (stream.stream_id,))
        elif status == "enabled" and stream.status != "enabled":
            await db.execute(
                "UPDATE set_outbox SET next_attempt_at = 0 WHERE stream_id = ? AND status = 'pending'",
                (stream.stream_id,),
            )

        await db.execute(
            """
            UPDATE streams
            SET aud = ?, endpoint_url = ?, endpoint_token = ?, events_requested = ?, status = ?
            WHERE stream_id = ?
            """,
            (aud, endpoint_url, stored_endpoint_token, json.dumps(events_requested), status, stream.stream_id),
        )
        await db.commit()

    updated = Stream(
        stream.stream_id,
        aud,
        endpoint_url,
        runtime_endpoint_token,
        events_requested,
        status,
        stream.created_at,
    )
    logger.info(
        "Updated SSF stream stream_id=%s aud=%s status=%s",
        sanitize_for_log(updated.stream_id),
        sanitize_for_log(updated.aud),
        updated.status,
    )
    return updated


async def delete_stream() -> bool:
    """Delete the current stream; returns True if a stream was deleted, False if none existed."""
    stream = await get_first_stream()
    if not stream:
        return False
    return await delete_stream_by_id(stream.stream_id)


async def delete_stream_by_id(stream_id: str) -> bool:
    """Delete a specific stream by ID; returns True if deleted, False if not found."""
    async with stream_operation_lock(), aiosqlite.connect(settings.database_path) as db:
        await db.execute("BEGIN IMMEDIATE")
        cursor = await db.execute("DELETE FROM streams WHERE stream_id = ?", (stream_id,))
        if cursor.rowcount > 0:
            await db.execute("DELETE FROM set_outbox WHERE stream_id = ? AND status = 'pending'", (stream_id,))
        await db.commit()
        deleted = cursor.rowcount > 0
    if deleted:
        logger.info("Deleted SSF stream stream_id=%s", sanitize_for_log(stream_id))
    return deleted


async def enqueue_outbox(deliveries: list[tuple[Stream, dict[str, Any]]]) -> int:
    """Atomically persist encrypted deliveries if each stream is still unchanged and enabled."""
    if not deliveries:
        return 0
    now = int(time.time())
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("BEGIN IMMEDIATE")
        for stream, _ in deliveries:
            cursor = await db.execute("SELECT * FROM streams WHERE stream_id = ?", (stream.stream_id,))
            row = await cursor.fetchone()
            if row is None:
                raise StreamChangedError("Stream no longer exists")
            current = _row_to_stream(row)
            if current != stream or current.status != "enabled":
                raise StreamChangedError("Stream changed before delivery could be queued")

        cursor = await db.execute("SELECT COUNT(*) FROM set_outbox")
        count_row = await cursor.fetchone()
        if count_row is None:
            raise RuntimeError("SQLite returned no row while checking outbox capacity")
        stored_items = count_row[0]
        if stored_items + len(deliveries) > MAX_OUTBOX_ITEMS:
            raise OutboxFullError("Delivery queue is full")

        await db.executemany(
            """
            INSERT INTO set_outbox (stream_id, payload, created_at, next_attempt_at)
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    stream.stream_id,
                    encrypt_sensitive_data(json.dumps(payload, separators=(",", ":"), ensure_ascii=True)),
                    now,
                    now,
                )
                for stream, payload in deliveries
            ],
        )
        await db.commit()
    return len(deliveries)


async def get_due_outbox(limit: int = 25) -> list[OutboxItem]:
    """Return due pending deliveries in FIFO order."""
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT id, stream_id, payload, created_at, attempts
            FROM set_outbox
            WHERE status = 'pending' AND next_attempt_at <= ?
            ORDER BY created_at, id
            LIMIT ?
            """,
            (int(time.time()), limit),
        )
        rows = await cursor.fetchall()
    return [OutboxItem(**dict(row)) for row in rows]


async def get_due_outbox_item(item_id: int) -> OutboxItem | None:
    """Re-read an item after acquiring the stream operation lock."""
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT id, stream_id, payload, created_at, attempts
            FROM set_outbox
            WHERE id = ? AND status = 'pending' AND next_attempt_at <= ?
            """,
            (item_id, int(time.time())),
        )
        row = await cursor.fetchone()
    return OutboxItem(**dict(row)) if row else None


async def complete_outbox_item(item_id: int) -> None:
    """Remove a successfully delivered SET from the outbox."""
    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute("DELETE FROM set_outbox WHERE id = ? AND status = 'pending'", (item_id,))
        await db.commit()


async def retry_outbox_item(item_id: int, attempts: int, next_attempt_at: int, reason: str) -> None:
    """Persist an attempt failure and its next retry time."""
    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute(
            """
            UPDATE set_outbox
            SET attempts = ?, next_attempt_at = ?, last_error = ?
            WHERE id = ? AND status = 'pending'
            """,
            (attempts, next_attempt_at, reason, item_id),
        )
        await db.commit()


async def block_outbox_item(item_id: int, reason: str) -> None:
    """Stop retrying an item that cannot be safely decrypted or parsed."""
    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute(
            "UPDATE set_outbox SET status = 'blocked', last_error = ? WHERE id = ? AND status = 'pending'",
            (reason, item_id),
        )
        await db.commit()


async def cancel_outbox_item(item_id: int) -> None:
    """Remove a pending delivery whose stream was removed or replaced."""
    async with aiosqlite.connect(settings.database_path) as db:
        await db.execute("DELETE FROM set_outbox WHERE id = ? AND status = 'pending'", (item_id,))
        await db.commit()


async def requeue_blocked_outbox() -> int:
    """Make blocked deliveries retryable after an operator restores the encryption key."""
    async with aiosqlite.connect(settings.database_path) as db:
        cursor = await db.execute(
            """
            UPDATE set_outbox
            SET status = 'pending', attempts = 0, next_attempt_at = ?, last_error = NULL
            WHERE status = 'blocked'
            """,
            (int(time.time()),),
        )
        await db.commit()
    return cursor.rowcount


async def delete_blocked_outbox() -> int:
    """Discard blocked deliveries that an operator has decided cannot be recovered."""
    async with aiosqlite.connect(settings.database_path) as db:
        cursor = await db.execute("DELETE FROM set_outbox WHERE status = 'blocked'")
        await db.commit()
    return cursor.rowcount


async def delete_pending_outbox() -> int:
    """Discard all pending deliveries when an operator explicitly chooses data loss."""
    async with stream_operation_lock(), aiosqlite.connect(settings.database_path) as db:
        cursor = await db.execute("DELETE FROM set_outbox WHERE status = 'pending'")
        await db.commit()
    return cursor.rowcount


async def get_outbox_status() -> dict[str, int | None]:
    """Return queue counters and the oldest pending timestamp, without payload data."""
    async with aiosqlite.connect(settings.database_path) as db:
        cursor = await db.execute(
            """
            SELECT
              COUNT(*) FILTER (WHERE status = 'pending') AS pending,
              COUNT(*) FILTER (WHERE status = 'blocked') AS blocked,
              MIN(created_at) FILTER (WHERE status = 'pending') AS oldest_pending_at,
              COUNT(*) AS stored
            FROM set_outbox
            """
        )
        row = await cursor.fetchone()
    if row is None:
        raise RuntimeError("SQLite returned no aggregate row for outbox status")
    return {
        "pending": row[0],
        "blocked": row[1],
        "oldest_pending_at": row[2],
        "stored": row[3],
        "capacity": MAX_OUTBOX_ITEMS,
    }


async def decrypt_outbox_payload(item: OutboxItem) -> dict[str, Any]:
    """Decrypt and parse a queued delivery payload."""
    try:
        payload = json.loads(decrypt_sensitive_data(item.payload))
    except (EncryptedDataError, json.JSONDecodeError) as exc:
        raise EncryptedDataError("Stored delivery payload cannot be read") from exc
    if not isinstance(payload, dict):
        raise EncryptedDataError("Stored delivery payload has an invalid shape")
    return payload
