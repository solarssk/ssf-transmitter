"""Regression test for a lost-update race in app.database's stream mutations.

Real production bug: update_stream() reads the current row, selectively
preserves fields the caller didn't supply (notably endpoint_token), then
writes the merged result back. Two concurrent update_stream() calls could
interleave so the second commit's write silently reverted the first's (e.g.
a token rotation reverted by a concurrent status-only PATCH that read the
pre-rotation token) — reproduced with a forced interleaving before the fix.
"""

from __future__ import annotations

import asyncio

import aiosqlite
import pytest

from app.database import create_stream, delete_stream, init_db, update_stream


@pytest.fixture(autouse=True)
async def _reset_streams():
    await init_db()
    yield
    await delete_stream()


@pytest.mark.anyio
async def test_update_stream_serializes_concurrent_writes(monkeypatch):
    """The write lock must hold for a whole read-modify-write cycle: no two
    update_stream() (or create_stream()/delete_stream_by_id()) critical
    sections may ever be in flight at the same time.
    """
    await create_stream(
        {
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://receiver.example.test/events",
                "endpoint_url_token": "original-token",
            },
        }
    )

    active = 0
    max_active = 0
    real_execute = aiosqlite.Connection.execute

    async def tracking_execute(self, *args, **kwargs):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        try:
            # Yield control so a concurrent, unlocked call would get a
            # chance to interleave here if the lock weren't enforcing
            # exclusion around the whole critical section.
            await asyncio.sleep(0.01)
            return await real_execute(self, *args, **kwargs)
        finally:
            active -= 1

    monkeypatch.setattr(aiosqlite.Connection, "execute", tracking_execute)

    await asyncio.gather(
        update_stream({"status": "enabled"}),
        update_stream({"delivery": {"endpoint_url_token": "rotated-token"}}),
    )

    assert max_active == 1


@pytest.mark.anyio
async def test_update_stream_does_not_lose_concurrent_token_rotation():
    """End-to-end sanity check: a status-only update racing a token
    rotation must never leave the pre-rotation token stored — whichever
    update's read-modify-write cycle runs last must observe the other's
    already-committed write, not a stale pre-write snapshot.
    """
    await create_stream(
        {
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://receiver.example.test/events",
                "endpoint_url_token": "original-token",
            },
        }
    )

    await asyncio.gather(
        update_stream({"status": "enabled"}),
        update_stream({"delivery": {"endpoint_url_token": "rotated-token"}}),
    )

    from app.database import get_first_stream

    stream = await get_first_stream()
    assert stream is not None
    assert stream.endpoint_token == "rotated-token"
