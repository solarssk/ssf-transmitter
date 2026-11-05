import asyncio
from dataclasses import replace

import aiosqlite
import pytest

import app.crypto as crypto
import app.database as database
from app.database import Stream, StreamChangedError
from app.events import outbox
from app.events.mapper import SESSION_REVOKED, MappedEvent


def test_sensitive_data_encryption_fails_closed_for_wrong_key(monkeypatch):
    monkeypatch.setattr(crypto, "settings", replace(crypto.settings, ssf_token_encryption_key="first-key"))
    ciphertext = crypto.encrypt_sensitive_data("sensitive-set")
    monkeypatch.setattr(crypto, "settings", replace(crypto.settings, ssf_token_encryption_key="second-key"))

    with pytest.raises(crypto.EncryptedDataError):
        crypto.decrypt_sensitive_data(ciphertext)


@pytest.fixture
async def queued_stream(tmp_path, monkeypatch):
    db_path = tmp_path / "outbox.db"
    monkeypatch.setattr(database, "settings", replace(database.settings, database_path=str(db_path)))
    await database.init_db()
    stream = Stream(
        stream_id="outbox-test-stream",
        aud="receiver-audience",
        endpoint_url="https://receiver.example.test/events",
        endpoint_token="receiver-secret-token",
        events_requested=[],
        status="enabled",
        created_at=1,
    )
    await database.save_stream(stream)
    monkeypatch.setattr(outbox, "sign_set", lambda **kwargs: "signed-set-token")
    return db_path, stream


async def _enqueue(stream: Stream) -> int:
    return await outbox.enqueue_events(
        [stream],
        [MappedEvent(uri=SESSION_REVOKED, payload={}, txn="test-transaction")],
        "user@example.com",
    )


@pytest.mark.anyio
async def test_existing_database_upgrade_preserves_stream_and_creates_outbox(tmp_path, monkeypatch):
    db_path = tmp_path / "existing.db"
    monkeypatch.setattr(database, "settings", replace(database.settings, database_path=str(db_path)))
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """
            CREATE TABLE streams (
                stream_id TEXT PRIMARY KEY, aud TEXT NOT NULL, endpoint_url TEXT NOT NULL,
                endpoint_token TEXT NOT NULL, events_requested TEXT NOT NULL,
                status TEXT DEFAULT 'enabled', created_at INTEGER NOT NULL
            )
            """
        )
        await db.execute(
            "INSERT INTO streams VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "existing-stream",
                "receiver-audience",
                "https://receiver.example.test/events",
                crypto.encrypt_token("existing-token"),
                "[]",
                "enabled",
                1,
            ),
        )
        await db.commit()

    await database.init_db()
    stream = await database.get_first_stream()
    assert stream is not None
    assert stream.stream_id == "existing-stream"
    assert stream.endpoint_token == "existing-token"
    assert stream.status == "enabled"
    assert (await database.get_outbox_status())["stored"] == 0


@pytest.mark.anyio
async def test_outbox_encrypts_payload_and_survives_database_reinitialization(queued_stream, monkeypatch):
    db_path, stream = queued_stream

    assert await _enqueue(stream) == 1
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("SELECT payload FROM set_outbox")
        (ciphertext,) = await cursor.fetchone()
        assert ciphertext.startswith("fernet1:")
        assert "user@example.com" not in ciphertext
        assert "receiver-secret-token" not in ciphertext
        assert "signed-set-token" not in ciphertext

    async def fake_push_signed_set(*args):
        return True

    monkeypatch.setattr(outbox, "push_signed_set", fake_push_signed_set)
    await database.init_db()
    await outbox.deliver_pending()
    status = await database.get_outbox_status()
    assert status["pending"] == 0


@pytest.mark.anyio
async def test_outbox_retries_failures_and_removes_successful_delivery(queued_stream, monkeypatch):
    db_path, stream = queued_stream
    await _enqueue(stream)
    results = iter([False, True])

    async def fake_push_signed_set(*args):
        return next(results)

    monkeypatch.setattr(outbox, "push_signed_set", fake_push_signed_set)
    await outbox.deliver_pending()
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("SELECT attempts, next_attempt_at FROM set_outbox")
        attempts, next_attempt_at = await cursor.fetchone()
    assert attempts == 1
    assert next_attempt_at > 0

    async with aiosqlite.connect(db_path) as db:
        await db.execute("UPDATE set_outbox SET next_attempt_at = 0")
        await db.commit()
    await outbox.deliver_pending()
    status = await database.get_outbox_status()
    assert status["pending"] == 0
    assert status["stored"] == 0


@pytest.mark.anyio
async def test_delivery_is_retried_with_same_token_if_success_cannot_be_recorded(queued_stream, monkeypatch):
    _, stream = queued_stream
    await _enqueue(stream)
    sent_tokens = []

    async def fake_push_signed_set(stream, token, event_uri):
        sent_tokens.append(token)
        return True

    async def fail_completion(item_id):
        raise OSError("database unavailable")

    complete_item = outbox.complete_outbox_item
    monkeypatch.setattr(outbox, "push_signed_set", fake_push_signed_set)
    monkeypatch.setattr(outbox, "complete_outbox_item", fail_completion)
    with pytest.raises(OSError, match="database unavailable"):
        await outbox.deliver_pending()
    assert (await database.get_outbox_status())["pending"] == 1

    monkeypatch.setattr(outbox, "complete_outbox_item", complete_item)
    await outbox.deliver_pending()
    assert sent_tokens == ["signed-set-token", "signed-set-token"]
    assert (await database.get_outbox_status())["pending"] == 0


@pytest.mark.anyio
async def test_pending_discard_waits_for_inflight_delivery_and_skips_stale_batch(queued_stream, monkeypatch):
    _, stream = queued_stream
    await _enqueue(stream)
    await _enqueue(stream)
    started = asyncio.Event()
    finish = asyncio.Event()
    sent = []

    async def fake_push_signed_set(*args):
        sent.append(args)
        started.set()
        await finish.wait()
        return True

    monkeypatch.setattr(outbox, "push_signed_set", fake_push_signed_set)
    delivery = asyncio.create_task(outbox.deliver_pending())
    await asyncio.wait_for(started.wait(), timeout=5)
    discard = asyncio.create_task(database.delete_pending_outbox())
    await asyncio.sleep(0)
    assert not discard.done()

    finish.set()
    assert await asyncio.wait_for(discard, timeout=5) == 1
    assert await asyncio.wait_for(delivery, timeout=5) == 1
    assert len(sent) == 1
    assert (await database.get_outbox_status())["pending"] == 0


@pytest.mark.anyio
async def test_pause_waits_for_inflight_delivery_and_holds_remaining_batch(queued_stream, monkeypatch):
    _, stream = queued_stream
    await _enqueue(stream)
    await _enqueue(stream)
    started = asyncio.Event()
    finish = asyncio.Event()
    sent = []

    async def fake_push_signed_set(*args):
        sent.append(args)
        started.set()
        await finish.wait()
        return True

    monkeypatch.setattr(outbox, "push_signed_set", fake_push_signed_set)
    delivery = asyncio.create_task(outbox.deliver_pending())
    await asyncio.wait_for(started.wait(), timeout=5)
    pause = asyncio.create_task(database.update_stream({"status": "paused"}))
    await asyncio.sleep(0)
    assert not pause.done()

    finish.set()
    assert (await asyncio.wait_for(pause, timeout=5)).status == "paused"
    await asyncio.wait_for(delivery, timeout=5)
    assert len(sent) == 1
    assert (await database.get_outbox_status())["pending"] == 1


@pytest.mark.anyio
async def test_delivery_loop_finishes_inflight_item_before_stopping(queued_stream, monkeypatch):
    _, stream = queued_stream
    await _enqueue(stream)
    await _enqueue(stream)
    started = asyncio.Event()
    finish = asyncio.Event()
    stop = asyncio.Event()
    sent = []

    async def fake_push_signed_set(*args):
        sent.append(args)
        started.set()
        await finish.wait()
        return True

    monkeypatch.setattr(outbox, "push_signed_set", fake_push_signed_set)
    worker = asyncio.create_task(outbox.delivery_loop(stop))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        stop.set()
        await asyncio.sleep(0)
        assert not worker.done()
    finally:
        finish.set()
        await asyncio.wait_for(worker, timeout=1)

    assert len(sent) == 1
    assert (await database.get_outbox_status())["pending"] == 1


@pytest.mark.anyio
async def test_lifespan_waits_for_delivery_worker_database_operation(monkeypatch):
    import app.main as main

    started = asyncio.Event()
    finish = asyncio.Event()
    cancelled = False

    async def slow_due_outbox():
        nonlocal cancelled
        started.set()
        try:
            await finish.wait()
        except asyncio.CancelledError:
            cancelled = True
            raise
        return []

    async def skip_database_init():
        pass

    monkeypatch.setattr(outbox, "get_due_outbox", slow_due_outbox)
    monkeypatch.setattr(main, "run_preflight_checks", lambda: None)
    monkeypatch.setattr(main, "ensure_keys", lambda: None)
    monkeypatch.setattr(main, "init_db", skip_database_init)
    monkeypatch.setattr(main, "quarantine_undecryptable_receiver_tokens", lambda: None)
    monkeypatch.setattr(main, "settings", replace(main.settings, apple_scim_client_id=None))

    async def run_lifespan():
        async with main.lifespan(main.app):
            await started.wait()

    task = asyncio.create_task(run_lifespan())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        finish.set()
        await asyncio.wait_for(task, timeout=1)
    assert not cancelled


@pytest.mark.anyio
async def test_delivery_deadline_schedules_retry(queued_stream, monkeypatch):
    db_path, stream = queued_stream
    await _enqueue(stream)

    async def stalled_push(*args):
        await asyncio.Event().wait()
        return True

    monkeypatch.setattr(outbox, "push_signed_set", stalled_push)
    monkeypatch.setattr(outbox, "_DELIVERY_DEADLINE_SECONDS", 0.01)
    await outbox.deliver_pending()
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute("SELECT attempts, last_error FROM set_outbox")
        assert await cursor.fetchone() == (1, "delivery_timeout")


@pytest.mark.anyio
async def test_paused_stream_holds_queue_and_resume_makes_it_due(queued_stream, monkeypatch):
    _, stream = queued_stream
    await _enqueue(stream)
    paused = await database.update_stream({"status": "paused"})
    assert paused is not None
    attempted = []

    async def fake_push_signed_set(*args):
        attempted.append(args)
        return True

    monkeypatch.setattr(outbox, "push_signed_set", fake_push_signed_set)
    await outbox.deliver_pending()
    assert attempted == []
    assert (await database.get_outbox_status())["pending"] == 1

    await database.update_stream({"status": "enabled"})
    await outbox.deliver_pending()
    assert len(attempted) == 1
    assert (await database.get_outbox_status())["pending"] == 0


@pytest.mark.anyio
async def test_stream_configuration_change_cancels_pending_delivery(queued_stream):
    _, stream = queued_stream
    await _enqueue(stream)

    updated = await database.update_stream({"aud": "new-audience"})

    assert updated is not None
    assert (await database.get_outbox_status())["pending"] == 0
    with pytest.raises(StreamChangedError):
        await database.enqueue_outbox([(stream, {"token": "stale"})])


@pytest.mark.anyio
async def test_full_queue_rejects_new_delivery_without_discarding_existing_item(queued_stream, monkeypatch):
    _, stream = queued_stream
    monkeypatch.setattr(database, "MAX_OUTBOX_ITEMS", 1)

    assert await _enqueue(stream) == 1
    with pytest.raises(database.OutboxFullError):
        await _enqueue(stream)

    status = await database.get_outbox_status()
    assert status["pending"] == 1
    assert status["stored"] == 1
    assert status["capacity"] == 1


@pytest.mark.anyio
async def test_replacing_or_deleting_stream_cancels_pending_delivery(queued_stream):
    _, stream = queued_stream
    await _enqueue(stream)
    replacement = Stream(
        stream_id="replacement-stream",
        aud="new-audience",
        endpoint_url="https://replacement.example.test/events",
        endpoint_token="new-token",
        events_requested=[],
        status="enabled",
        created_at=2,
    )

    await database.save_stream(replacement)
    assert (await database.get_outbox_status())["pending"] == 0

    await _enqueue(replacement)
    assert await database.delete_pending_outbox() == 1
    assert (await database.get_outbox_status())["pending"] == 0

    await _enqueue(replacement)
    assert await database.delete_stream_by_id(replacement.stream_id)
    assert (await database.get_outbox_status())["pending"] == 0


@pytest.mark.anyio
async def test_failed_stream_replacement_preserves_pending_delivery(queued_stream, monkeypatch):
    _, stream = queued_stream
    await _enqueue(stream)
    replacement = replace(stream, stream_id="failed-replacement", endpoint_token="new-token")

    def fail_encryption(token):
        raise RuntimeError("encryption failed")

    monkeypatch.setattr(database, "encrypt_token", fail_encryption)
    with pytest.raises(RuntimeError, match="encryption failed"):
        await database.save_stream(replacement)

    assert (await database.get_outbox_status())["pending"] == 1


@pytest.mark.anyio
async def test_unreadable_payload_is_blocked_and_operator_can_retry_or_discard(queued_stream):
    db_path, stream = queued_stream
    await _enqueue(stream)
    async with aiosqlite.connect(db_path) as db:
        await db.execute("UPDATE set_outbox SET payload = 'not-encrypted'")
        await db.commit()

    await outbox.deliver_pending()
    status = await database.get_outbox_status()
    assert status["pending"] == 0
    assert status["blocked"] == 1
    assert await database.requeue_blocked_outbox() == 1
    assert (await database.get_outbox_status())["pending"] == 1

    await outbox.deliver_pending()
    status = await database.get_outbox_status()
    assert status["pending"] == 0
    assert status["blocked"] == 1
    assert await database.delete_blocked_outbox() == 1
    assert (await database.get_outbox_status())["blocked"] == 0
