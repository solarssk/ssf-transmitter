"""Tests for app.alerts.send_alert — webhook delivery, cooldown, and error handling."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import ClassVar

import httpx
import pytest

from app import alerts


class FakeResponse:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code


class FakeAsyncClient:
    # Deliberately class-level, not per-instance — see test_pusher.py's
    # FakeAsyncClient for why (tests monkeypatch these directly on the class).
    requests: ClassVar[list[tuple]] = []
    response: ClassVar[FakeResponse] = FakeResponse()
    raise_error: ClassVar[Exception | None] = None

    def __init__(self, timeout: float):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json):
        if self.raise_error is not None:
            raise self.raise_error
        self.requests.append((url, json))
        return self.response


def _settings(webhook_url: str | None = "https://alerts.example.test/hook"):
    return SimpleNamespace(
        apple_scim_alert_webhook_url=webhook_url,
        public_url=lambda path: f"https://idp.example.test{path}",
    )


@pytest.fixture(autouse=True)
def _reset_alert_state(monkeypatch):
    """Clear cooldown state and FakeAsyncClient state before every test."""
    alerts._last_sent.clear()
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "response", FakeResponse())
    monkeypatch.setattr(FakeAsyncClient, "raise_error", None)
    monkeypatch.setattr(alerts.httpx, "AsyncClient", FakeAsyncClient)


@pytest.mark.anyio
async def test_noop_when_webhook_not_configured(monkeypatch):
    monkeypatch.setattr("app.config.settings", _settings(webhook_url=None))

    await alerts.send_alert(event="scim_client_secret_expired", message="expired")

    assert FakeAsyncClient.requests == []


@pytest.mark.anyio
async def test_posts_expected_payload(monkeypatch):
    monkeypatch.setattr("app.config.settings", _settings())

    await alerts.send_alert(event="scim_client_secret_expired", message="expired", severity="critical")

    assert len(FakeAsyncClient.requests) == 1
    url, payload = FakeAsyncClient.requests[0]
    assert url == "https://alerts.example.test/hook"
    assert payload["event"] == "scim_client_secret_expired"
    assert payload["severity"] == "critical"
    assert payload["message"] == "expired"
    assert payload["authorize_url"] == "https://idp.example.test/apple-scim/authorize"
    assert "timestamp" in payload


@pytest.mark.anyio
async def test_second_alert_within_cooldown_is_suppressed(monkeypatch):
    monkeypatch.setattr("app.config.settings", _settings())

    await alerts.send_alert(event="scim_client_secret_expired", message="first")
    await alerts.send_alert(event="scim_client_secret_expired", message="second")

    assert len(FakeAsyncClient.requests) == 1


@pytest.mark.anyio
async def test_alert_resent_after_cooldown_expires(monkeypatch):
    monkeypatch.setattr("app.config.settings", _settings())

    await alerts.send_alert(event="scim_client_secret_expired", message="first")

    future = alerts._last_sent["scim_client_secret_expired"] + alerts.ALERT_COOLDOWN + 1
    monkeypatch.setattr(alerts.time, "monotonic", lambda: future)
    await alerts.send_alert(event="scim_client_secret_expired", message="second")

    assert len(FakeAsyncClient.requests) == 2


@pytest.mark.anyio
async def test_different_events_are_not_coalesced_by_cooldown(monkeypatch):
    monkeypatch.setattr("app.config.settings", _settings())

    await alerts.send_alert(event="scim_client_secret_expired", message="a")
    await alerts.send_alert(event="scim_reauth_needed", message="b")

    assert len(FakeAsyncClient.requests) == 2


@pytest.mark.anyio
async def test_network_error_is_swallowed(monkeypatch, caplog):
    monkeypatch.setattr("app.config.settings", _settings())
    monkeypatch.setattr(FakeAsyncClient, "raise_error", httpx.ConnectError("connection refused"))

    with caplog.at_level(logging.WARNING, logger="app.alerts"):
        await alerts.send_alert(event="scim_client_secret_expired", message="unreachable")

    assert "unreachable" in caplog.text.lower() or "Alert webhook unreachable" in caplog.text


@pytest.mark.anyio
async def test_network_error_does_not_start_cooldown(monkeypatch):
    """A failed delivery attempt (server unreachable) must not be treated as 'sent' —
    the next attempt should still go through immediately, not wait out the cooldown."""
    monkeypatch.setattr("app.config.settings", _settings())
    monkeypatch.setattr(FakeAsyncClient, "raise_error", httpx.ConnectError("connection refused"))

    await alerts.send_alert(event="scim_client_secret_expired", message="first")
    assert "scim_client_secret_expired" not in alerts._last_sent


@pytest.mark.anyio
async def test_unexpected_exception_is_swallowed(monkeypatch, caplog):
    monkeypatch.setattr("app.config.settings", _settings())
    monkeypatch.setattr(FakeAsyncClient, "raise_error", ValueError("boom"))

    with caplog.at_level(logging.WARNING, logger="app.alerts"):
        await alerts.send_alert(event="scim_client_secret_expired", message="oops")

    assert "unexpected error" in caplog.text.lower()


@pytest.mark.anyio
async def test_non_2xx_response_logs_warning_but_still_sets_cooldown(monkeypatch, caplog):
    monkeypatch.setattr("app.config.settings", _settings())
    monkeypatch.setattr(FakeAsyncClient, "response", FakeResponse(status_code=500))

    with caplog.at_level(logging.WARNING, logger="app.alerts"):
        await alerts.send_alert(event="scim_client_secret_expired", message="first")

    assert "non-2xx" in caplog.text.lower() or "500" in caplog.text
    assert "scim_client_secret_expired" in alerts._last_sent

    # Cooldown still applies even though delivery "succeeded" with a non-2xx status.
    await alerts.send_alert(event="scim_client_secret_expired", message="second")
    assert len(FakeAsyncClient.requests) == 1
