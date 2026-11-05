"""Regression tests for overlapping Apple SCIM syncs and OAuth operations."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import shlex
import time
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from uvicorn import Config

from app import main
from app.config import settings as real_settings
from app.routes import apple_scim as routes
from app.scim import token as token_mod
from app.scim.apple import AppleUserListError, SyncResult
from app.scim.coordination import scim_operation


def test_image_runs_one_worker_even_with_web_concurrency_set(monkeypatch):
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    command = next(line.removeprefix("CMD ") for line in dockerfile.read_text().splitlines() if line.startswith("CMD "))
    shell_args = shlex.split(json.loads(command)[-1])
    assert shell_args.count("--workers") == 1
    assert shell_args[shell_args.index("--workers") + 1] == "1"

    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    assert Config("app.main:app", workers=1).workers == 1


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    settings = dataclasses.replace(
        real_settings,
        apple_scim_client_id="client-id",
        apple_scim_client_secret="client-secret",
        authentik_url="https://authentik.example.test",
        authentik_token="authentik-token",
    )
    monkeypatch.setattr(routes, "settings", settings)
    routes._pending_states.clear()
    yield
    routes._pending_states.clear()


def _stub_sync(monkeypatch):
    started = asyncio.Event()
    release = asyncio.Event()
    calls = []
    current_token = ["old-token"]

    async def get_token():
        token = current_token[0]
        calls.append(("token", token))
        return token

    async def get_users():
        calls.append(("users", None))
        started.set()
        await release.wait()
        return []

    async def sync_users(token, users):
        calls.append(("sync", token))
        return SyncResult()

    monkeypatch.setattr(routes, "get_valid_access_token", get_token)
    monkeypatch.setattr(routes, "get_users", get_users)
    monkeypatch.setattr(routes, "sync_users", sync_users)
    monkeypatch.setattr("app.scim.token.get_valid_access_token", get_token)
    monkeypatch.setattr("app.scim.authentik.get_users", get_users)
    monkeypatch.setattr("app.scim.apple.sync_users", sync_users)
    return started, release, calls, current_token


@pytest.mark.anyio
async def test_manual_and_scheduled_sync_do_not_overlap(monkeypatch):
    started, release, calls, current_token = _stub_sync(monkeypatch)
    first = asyncio.create_task(routes.sync())
    scheduled = None
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        with pytest.raises(HTTPException) as exc:
            await asyncio.wait_for(routes.sync(), timeout=1)
        assert exc.value.status_code == 409

        scheduled = asyncio.create_task(main._run_scheduled_apple_scim_sync())
        await asyncio.sleep(0)
        assert not scheduled.done()
        assert calls == [("token", "old-token"), ("users", None)]
        current_token[0] = "latest-token"
    finally:
        release.set()
        await asyncio.wait_for(first, timeout=1)
        if scheduled is not None:
            await asyncio.wait_for(scheduled, timeout=1)

    assert calls == [
        ("token", "old-token"),
        ("users", None),
        ("sync", "old-token"),
        ("token", "latest-token"),
        ("users", None),
        ("sync", "latest-token"),
    ]


@pytest.mark.anyio
async def test_manual_sync_is_rejected_while_scheduled_sync_is_running(monkeypatch):
    started, release, calls, _ = _stub_sync(monkeypatch)
    scheduled = asyncio.create_task(main._run_scheduled_apple_scim_sync())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        with pytest.raises(HTTPException) as exc:
            await asyncio.wait_for(routes.sync(), timeout=1)
        assert exc.value.status_code == 409
        assert calls == [("token", "old-token"), ("users", None)]
    finally:
        release.set()
        await asyncio.wait_for(scheduled, timeout=1)

    assert calls == [("token", "old-token"), ("users", None), ("sync", "old-token")]


@pytest.mark.anyio
async def test_scheduled_sync_without_token_sends_alert_and_releases_gate(monkeypatch):
    calls = []

    async def no_token():
        return None

    async def send_alert(**kwargs):
        calls.append(kwargs["event"])

    async def get_users():
        calls.append("users")
        return []

    monkeypatch.setattr("app.scim.token.get_valid_access_token", no_token)
    monkeypatch.setattr("app.scim.authentik.get_users", get_users)
    monkeypatch.setattr("app.alerts.send_alert", send_alert)

    await main._run_scheduled_apple_scim_sync()

    assert calls == ["scim_no_valid_token"]
    async with scim_operation():
        pass


@pytest.mark.anyio
async def test_scheduled_sync_logs_incomplete_apple_listing_and_releases_gate(monkeypatch, caplog):
    async def token():
        return "valid-token"

    async def users():
        return []

    async def fail_sync(access_token, scim_users):
        raise AppleUserListError("incomplete")

    monkeypatch.setattr("app.scim.token.get_valid_access_token", token)
    monkeypatch.setattr("app.scim.authentik.get_users", users)
    monkeypatch.setattr("app.scim.apple.sync_users", fail_sync)

    with caplog.at_level(logging.ERROR, logger="app.main"):
        await main._run_scheduled_apple_scim_sync()

    assert "scheduled sync aborted" in caplog.text
    async with scim_operation():
        pass


@pytest.mark.anyio
async def test_manual_sync_returns_http_409_when_another_sync_is_running(monkeypatch):
    started, release, calls, _ = _stub_sync(monkeypatch)
    headers = {"Authorization": f"Bearer {real_settings.ssf_management_token}"}
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = asyncio.create_task(client.post("/apple-scim/sync", headers=headers))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            second = await asyncio.wait_for(client.post("/apple-scim/sync", headers=headers), timeout=1)
            assert second.status_code == 409
            assert "in progress" in second.json()["detail"]
            assert calls == [("token", "old-token"), ("users", None)]
        finally:
            release.set()
            response = await asyncio.wait_for(first, timeout=1)

    assert response.status_code == 200


@pytest.mark.anyio
async def test_post_authorization_sync_waits_and_uses_latest_token(monkeypatch):
    started, release, calls, current_token = _stub_sync(monkeypatch)
    manual = asyncio.create_task(routes.sync())
    background = None
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        background = asyncio.create_task(routes._background_sync())
        await asyncio.sleep(0)
        assert not background.done()
        assert calls == [("token", "old-token"), ("users", None)]
        current_token[0] = "latest-token"
    finally:
        release.set()
        await asyncio.wait_for(manual, timeout=1)
        if background is not None:
            await asyncio.wait_for(background, timeout=1)

    assert calls == [
        ("token", "old-token"),
        ("users", None),
        ("sync", "old-token"),
        ("token", "latest-token"),
        ("users", None),
        ("sync", "latest-token"),
    ]


@pytest.mark.anyio
async def test_busy_callback_keeps_state_for_retry_and_does_not_exchange_code(monkeypatch):
    calls = []

    class Client:
        def __init__(self, timeout):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, data):
            calls.append(data["grant_type"])
            return httpx.Response(200, json={"access_token": "authorized-token", "expires_in": 3600})

    async def save(*args):
        calls.append("saved")

    async def token():
        return "authorized-token"

    async def users():
        return []

    async def sync_users(access_token, scim_users):
        calls.append("sync")
        return SyncResult()

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)
    monkeypatch.setattr(routes, "save_tokens", save)
    monkeypatch.setattr(routes, "get_valid_access_token", token)
    monkeypatch.setattr(routes, "get_users", users)
    monkeypatch.setattr(routes, "sync_users", sync_users)
    routes._add_state("valid-state")

    async with scim_operation():
        with pytest.raises(HTTPException) as exc:
            await routes.callback(code="code", state="valid-state")
        assert exc.value.status_code == 409
        assert "valid-state" in routes._pending_states
        assert calls == []

    response = await routes.callback(code="code", state="valid-state")
    await asyncio.gather(*routes._background_tasks)

    assert response["status"] == "authorized"
    assert "valid-state" not in routes._pending_states
    assert calls == ["authorization_code", "saved", "sync"]


@pytest.mark.anyio
async def test_callback_and_refresh_cannot_exchange_tokens_concurrently(monkeypatch):
    exchange_started = asyncio.Event()
    release_exchange = asyncio.Event()
    calls = []
    stored = {"access_token": "expired", "refresh_token": "old-refresh", "expires_at": 0}

    class Client:
        def __init__(self, timeout):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, data):
            calls.append(data["grant_type"])
            if data["grant_type"] == "authorization_code":
                exchange_started.set()
                await release_exchange.wait()
                return httpx.Response(
                    200,
                    json={"access_token": "authorized-token", "refresh_token": "new-refresh", "expires_in": 3600},
                )
            return httpx.Response(200, json={"access_token": "refreshed-token", "expires_in": 3600})

    async def load():
        return dict(stored)

    async def save(access_token, refresh_token, expires_in):
        stored.update(
            access_token=access_token,
            refresh_token=refresh_token or stored["refresh_token"],
            expires_at=int(time.time()) + expires_in,
        )

    async def users():
        return []

    async def sync_users(access_token, scim_users):
        return SyncResult()

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)
    monkeypatch.setattr(token_mod, "load_tokens", load)
    monkeypatch.setattr(routes, "save_tokens", save)
    monkeypatch.setattr(token_mod, "save_tokens", save)
    monkeypatch.setattr(routes, "get_users", users)
    monkeypatch.setattr(routes, "sync_users", sync_users)
    routes._add_state("valid-state")

    callback = asyncio.create_task(routes.callback(code="code", state="valid-state"))
    refresh = None
    try:
        await asyncio.wait_for(exchange_started.wait(), timeout=1)
        refresh = asyncio.create_task(token_mod.get_valid_access_token())
        await asyncio.sleep(0)
        assert calls == ["authorization_code"]
    finally:
        release_exchange.set()
        await asyncio.wait_for(callback, timeout=1)
        if refresh is not None:
            assert await asyncio.wait_for(refresh, timeout=1) == "authorized-token"
        await asyncio.gather(*routes._background_tasks)

    assert calls == ["authorization_code"]
    assert stored["refresh_token"] == "new-refresh"


@pytest.mark.anyio
async def test_callback_waits_for_in_progress_refresh_before_exchange(monkeypatch):
    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()
    calls = []
    stored = {"access_token": "expired", "refresh_token": "old-refresh", "expires_at": 0}

    class Client:
        def __init__(self, timeout):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, data):
            calls.append(data["grant_type"])
            if data["grant_type"] == "refresh_token":
                refresh_started.set()
                await release_refresh.wait()
                return httpx.Response(
                    200,
                    json={"access_token": "refreshed", "refresh_token": "rotated", "expires_in": 3600},
                )
            return httpx.Response(
                200,
                json={"access_token": "authorized", "refresh_token": "new-grant", "expires_in": 3600},
            )

    async def load():
        return dict(stored)

    async def save(access_token, refresh_token, expires_in):
        stored.update(
            access_token=access_token,
            refresh_token=refresh_token or stored["refresh_token"],
            expires_at=int(time.time()) + expires_in,
        )

    async def users():
        return []

    async def sync_users(access_token, scim_users):
        return SyncResult()

    monkeypatch.setattr(routes.httpx, "AsyncClient", Client)
    monkeypatch.setattr(token_mod, "settings", routes.settings)
    monkeypatch.setattr(token_mod, "load_tokens", load)
    monkeypatch.setattr(routes, "save_tokens", save)
    monkeypatch.setattr(token_mod, "save_tokens", save)
    monkeypatch.setattr(routes, "get_users", users)
    monkeypatch.setattr(routes, "sync_users", sync_users)
    routes._add_state("valid-state")

    refresh = asyncio.create_task(token_mod.get_valid_access_token())
    callback = None
    try:
        await asyncio.wait_for(refresh_started.wait(), timeout=1)
        callback = asyncio.create_task(routes.callback(code="code", state="valid-state"))
        await asyncio.sleep(0)
        assert calls == ["refresh_token"]
    finally:
        release_refresh.set()
        assert await asyncio.wait_for(refresh, timeout=1) == "refreshed"
        if callback is not None:
            assert (await asyncio.wait_for(callback, timeout=1))["status"] == "authorized"
        await asyncio.gather(*routes._background_tasks)

    assert calls == ["refresh_token", "authorization_code"]
    assert stored["access_token"] == "authorized"
    assert stored["refresh_token"] == "new-grant"


@pytest.mark.anyio
async def test_cancelled_operation_releases_sync_gate():
    started = asyncio.Event()

    async def hold():
        async with scim_operation():
            started.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(hold())
    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    async with scim_operation():
        pass
