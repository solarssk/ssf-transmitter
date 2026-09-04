"""Tests for app.main.lifespan — Apple SCIM background task shutdown handling."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

import pytest

from app import main


@pytest.fixture(autouse=True)
def _stub_startup(monkeypatch):
    """Skip real preflight/key/DB setup — this module tests shutdown, not startup."""
    monkeypatch.setattr(main, "run_preflight_checks", lambda: None)
    monkeypatch.setattr(main, "ensure_keys", lambda: None)
    monkeypatch.setattr(main, "quarantine_undecryptable_receiver_tokens", lambda: None)

    async def _noop_init_db() -> None:
        return None

    monkeypatch.setattr(main, "init_db", _noop_init_db)


@pytest.fixture
def _apple_scim_enabled(monkeypatch):
    """Enable the Apple SCIM background sync task for a test."""
    monkeypatch.setattr(
        main,
        "settings",
        replace(
            main.settings,
            apple_scim_client_id="client-id",
            apple_scim_client_secret="client-secret",
            authentik_url="https://authentik.example.test",
            authentik_token="authentik-token",
        ),
    )


@pytest.mark.anyio
async def test_lifespan_logs_stopped_on_cancellation(_apple_scim_enabled, monkeypatch, caplog):
    """Cancelling the background task on shutdown is logged, not raised out of lifespan()."""

    async def _sleep_forever() -> None:
        await asyncio.sleep(3600)

    monkeypatch.setattr(main, "_apple_scim_sync_loop", _sleep_forever)

    with caplog.at_level(logging.INFO, logger="app.main"):
        async with main.lifespan(main.app):
            pass  # nothing to do at "request time" — exiting triggers shutdown

    assert "Apple SCIM: sync loop stopped" in caplog.text


@pytest.mark.anyio
async def test_lifespan_logs_unexpected_error_from_sync_task(_apple_scim_enabled, monkeypatch, caplog):
    """A bug in the sync loop is surfaced at shutdown instead of disappearing silently."""

    async def _boom() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "_apple_scim_sync_loop", _boom)

    with caplog.at_level(logging.WARNING, logger="app.main"):
        async with main.lifespan(main.app):
            await asyncio.sleep(0.05)  # let the background task actually raise before shutdown runs

    assert "Apple SCIM: sync loop exited with an unexpected error" in caplog.text
