"""Tests for app.scim.token — Apple SCIM OAuth token storage and refresh.

Uses an isolated sqlite file per test (same pattern as test_startup.py) rather
than the shared test database, so tests can freely control expiry/refresh
state without cross-test interference.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from types import SimpleNamespace
from typing import ClassVar

import pytest

from app.scim import token as token_mod


def _init_tokens_table(db_path):
    with closing(sqlite3.connect(db_path)) as con:
        con.execute(
            """
            CREATE TABLE apple_scim_tokens (
              id            INTEGER PRIMARY KEY,
              access_token  TEXT NOT NULL,
              refresh_token TEXT,
              expires_at    INTEGER NOT NULL,
              updated_at    INTEGER NOT NULL
            )
            """
        )
        con.commit()


def _settings(db_path):
    return SimpleNamespace(
        database_path=str(db_path),
        apple_scim_client_id="client-id",
        apple_scim_client_secret="client-secret",
    )


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers: dict[str, str] = {}
        self.content = b""

    def json(self):
        return self._payload


class FakeAsyncClient:
    requests: ClassVar[list[dict]] = []
    response: ClassVar[FakeResponse] = FakeResponse(200)
    raise_error: ClassVar[Exception | None] = None

    def __init__(self, timeout: float):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, data):
        if self.raise_error is not None:
            raise self.raise_error
        self.requests.append({"url": url, "data": data})
        return self.response


class RaisingJSONResponse(FakeResponse):
    def json(self):
        raise ValueError("not json")


@pytest.fixture(autouse=True)
def _reset_fake_client(monkeypatch):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "response", FakeResponse(200))
    monkeypatch.setattr(FakeAsyncClient, "raise_error", None)
    monkeypatch.setattr(token_mod.httpx, "AsyncClient", FakeAsyncClient)


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "scim.db"
    _init_tokens_table(path)
    return path


# ---------------------------------------------------------------------------
# save_tokens / load_tokens
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_save_and_load_tokens_roundtrip(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))

    await token_mod.save_tokens("access-1", "refresh-1", 3600)
    loaded = await token_mod.load_tokens()

    assert loaded["access_token"] == "access-1"
    assert loaded["refresh_token"] == "refresh-1"
    # 60-second safety margin subtracted from the raw expiry.
    assert loaded["expires_at"] == pytest.approx(int(time.time()) + 3600 - 60, abs=2)


@pytest.mark.anyio
async def test_load_tokens_returns_none_when_empty(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))

    assert await token_mod.load_tokens() is None


@pytest.mark.anyio
async def test_save_tokens_preserves_refresh_token_when_none_provided(monkeypatch, db_path):
    """Apple does not always rotate the refresh token — a None here must not erase the stored one."""
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))

    await token_mod.save_tokens("access-1", "refresh-1", 3600)
    await token_mod.save_tokens("access-2", None, 3600)

    loaded = await token_mod.load_tokens()
    assert loaded["access_token"] == "access-2"
    assert loaded["refresh_token"] == "refresh-1"


# ---------------------------------------------------------------------------
# get_valid_access_token
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_get_valid_access_token_none_when_never_authorized(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))

    assert await token_mod.get_valid_access_token() is None
    assert FakeAsyncClient.requests == []


@pytest.mark.anyio
async def test_get_valid_access_token_returns_cached_when_not_expired(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    await token_mod.save_tokens("still-valid", "refresh-1", 3600)

    result = await token_mod.get_valid_access_token()

    assert result == "still-valid"
    assert FakeAsyncClient.requests == []  # no refresh attempted


@pytest.mark.anyio
async def test_get_valid_access_token_refreshes_when_expired(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    await token_mod.save_tokens("expired-token", "refresh-1", -3600)  # already in the past
    FakeAsyncClient.response = FakeResponse(200, {"access_token": "new-token", "expires_in": 3600})

    result = await token_mod.get_valid_access_token()

    assert result == "new-token"
    assert len(FakeAsyncClient.requests) == 1
    assert FakeAsyncClient.requests[0]["data"]["grant_type"] == "refresh_token"
    assert FakeAsyncClient.requests[0]["data"]["refresh_token"] == "refresh-1"

    persisted = await token_mod.load_tokens()
    assert persisted["access_token"] == "new-token"


# ---------------------------------------------------------------------------
# _refresh — error paths
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_refresh_returns_none_without_refresh_token(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))

    assert await token_mod._refresh(None) is None
    assert FakeAsyncClient.requests == []


@pytest.mark.anyio
async def test_refresh_network_error_returns_none(monkeypatch, db_path):
    import httpx

    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.raise_error = httpx.ConnectError("connection refused")

    assert await token_mod._refresh("refresh-1") is None


@pytest.mark.anyio
async def test_refresh_response_not_json_returns_none(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.response = RaisingJSONResponse(200)

    assert await token_mod._refresh("refresh-1") is None


@pytest.mark.anyio
async def test_refresh_missing_access_token_returns_none(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.response = FakeResponse(200, {"expires_in": 3600})

    assert await token_mod._refresh("refresh-1") is None


@pytest.mark.anyio
async def test_refresh_invalid_expires_in_defaults_to_3600(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.response = FakeResponse(200, {"access_token": "tok", "expires_in": "not-a-number"})

    result = await token_mod._refresh("refresh-1")

    assert result == "tok"
    persisted = await token_mod.load_tokens()
    # 3600 default minus the 60s safety margin.
    assert persisted["expires_at"] == pytest.approx(int(time.time()) + 3600 - 60, abs=2)


@pytest.mark.anyio
async def test_refresh_non_positive_expires_in_defaults_to_3600(monkeypatch, db_path):
    """expires_in that parses fine but is <= 0 is just as invalid as a non-numeric value."""
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.response = FakeResponse(200, {"access_token": "tok", "expires_in": 0})

    result = await token_mod._refresh("refresh-1")

    assert result == "tok"
    persisted = await token_mod.load_tokens()
    assert persisted["expires_at"] == pytest.approx(int(time.time()) + 3600 - 60, abs=2)


@pytest.mark.anyio
async def test_refresh_rotates_refresh_token(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    await token_mod.save_tokens("old-access", "old-refresh", 3600)
    FakeAsyncClient.response = FakeResponse(
        200, {"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600}
    )

    await token_mod._refresh("old-refresh")

    persisted = await token_mod.load_tokens()
    assert persisted["refresh_token"] == "new-refresh"


# ---------------------------------------------------------------------------
# _refresh — Apple client_secret expiry alerting
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("error_code", ["invalid_client", "invalid_grant", "unauthorized_client"])
async def test_refresh_client_secret_expiry_errors_send_alert(monkeypatch, db_path, error_code):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.response = FakeResponse(400, {"error": error_code})

    sent = []

    async def _fake_send_alert(**kwargs):
        sent.append(kwargs)

    monkeypatch.setattr(token_mod, "send_alert", _fake_send_alert)

    result = await token_mod._refresh("refresh-1")

    assert result is None
    assert len(sent) == 1
    assert sent[0]["event"] == "scim_client_secret_expired"
    assert sent[0]["severity"] == "critical"


@pytest.mark.anyio
async def test_refresh_unrecognized_error_does_not_send_alert(monkeypatch, db_path):
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.response = FakeResponse(500, {"error": "server_error"})

    sent = []

    async def _fake_send_alert(**kwargs):
        sent.append(kwargs)

    monkeypatch.setattr(token_mod, "send_alert", _fake_send_alert)

    result = await token_mod._refresh("refresh-1")

    assert result is None
    assert sent == []


@pytest.mark.anyio
async def test_refresh_error_response_not_json_does_not_crash(monkeypatch, db_path):
    """A non-200 response whose body isn't JSON must not raise while checking for error codes."""
    monkeypatch.setattr(token_mod, "settings", _settings(db_path))
    FakeAsyncClient.response = RaisingJSONResponse(400)

    result = await token_mod._refresh("refresh-1")

    assert result is None
