"""Tests for the Apple SCIM OAuth/sync HTTP routes (app/routes/apple_scim.py)."""

from __future__ import annotations

import dataclasses
from typing import ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import settings as real_settings
from app.main import app
from app.routes import apple_scim as scim_routes
from app.scim.apple import SyncResult

MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}


def _configured_settings(**overrides):
    defaults = dict(
        apple_scim_client_id="client-id",
        apple_scim_client_secret="client-secret",
        authentik_url="https://authentik.example.test",
        authentik_token="authentik-token",
    )
    defaults.update(overrides)
    return dataclasses.replace(real_settings, **defaults)


def _disabled_settings():
    return dataclasses.replace(
        real_settings,
        apple_scim_client_id=None,
        apple_scim_client_secret=None,
        authentik_url=None,
        authentik_token=None,
    )


@pytest.fixture(autouse=True)
def _clear_oauth_state():
    scim_routes._pending_states.clear()
    yield
    scim_routes._pending_states.clear()


@pytest.fixture
def client():
    with TestClient(app) as tc:
        yield tc


class FakeTokenResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers: dict[str, str] = {}
        self.content = b""

    def json(self):
        return self._payload


class FakeAsyncClient:
    response: ClassVar[FakeTokenResponse] = FakeTokenResponse(200)
    raise_error: ClassVar[Exception | None] = None
    last_request: ClassVar[dict | None] = None

    def __init__(self, timeout: float):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, data):
        if self.raise_error is not None:
            raise self.raise_error
        FakeAsyncClient.last_request = {"url": url, "data": data}
        return self.response


@pytest.fixture(autouse=True)
def _reset_fake_client(monkeypatch):
    monkeypatch.setattr(FakeAsyncClient, "response", FakeTokenResponse(200))
    monkeypatch.setattr(FakeAsyncClient, "raise_error", None)
    monkeypatch.setattr(FakeAsyncClient, "last_request", None)
    monkeypatch.setattr(scim_routes.httpx, "AsyncClient", FakeAsyncClient)


async def _noop_get_users():
    return []


async def _noop_sync_users(access_token, scim_users):
    return SyncResult()


@pytest.fixture(autouse=True)
def _stub_background_sync(monkeypatch):
    """Prevent the callback's fire-and-forget background sync from making real calls."""
    monkeypatch.setattr(scim_routes, "get_users", _noop_get_users)
    monkeypatch.setattr(scim_routes, "sync_users", _noop_sync_users)


# ---------------------------------------------------------------------------
# GET /apple-scim/authorize
# ---------------------------------------------------------------------------


def test_authorize_503_when_not_configured(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _disabled_settings())

    resp = client.get("/apple-scim/authorize", follow_redirects=False)

    assert resp.status_code == 503


def test_authorize_redirects_to_apple_with_state(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    resp = client.get("/apple-scim/authorize", follow_redirects=False)

    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert location.startswith(scim_routes.APPLE_AUTH_URL)
    assert "state=" in location
    assert "client_id=client-id" in location
    assert len(scim_routes._pending_states) == 1


# ---------------------------------------------------------------------------
# GET /apple-scim/callback
# ---------------------------------------------------------------------------


def test_callback_503_when_not_configured(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _disabled_settings())

    resp = client.get("/apple-scim/callback", params={"code": "x", "state": "y"})

    assert resp.status_code == 503


def test_callback_400_on_apple_error_param(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    resp = client.get("/apple-scim/callback", params={"error": "access_denied"})

    assert resp.status_code == 400
    assert "access_denied" in resp.json()["detail"]


def test_callback_400_missing_code(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    resp = client.get("/apple-scim/callback", params={"state": "some-state"})

    assert resp.status_code == 400
    assert "code" in resp.json()["detail"].lower()


def test_callback_400_missing_state(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    resp = client.get("/apple-scim/callback", params={"code": "some-code"})

    assert resp.status_code == 400
    assert "state" in resp.json()["detail"].lower()


def test_callback_400_unknown_state_rejected_as_csrf(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    resp = client.get("/apple-scim/callback", params={"code": "some-code", "state": "never-issued"})

    assert resp.status_code == 400
    assert "state" in resp.json()["detail"].lower()


def test_callback_400_state_is_single_use(client, monkeypatch):
    """A replayed (already-consumed) state must be rejected the second time."""
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("reused-state")
    monkeypatch.setattr(
        FakeAsyncClient, "response", FakeTokenResponse(200, {"access_token": "tok", "expires_in": 3600})
    )

    first = client.get("/apple-scim/callback", params={"code": "code-1", "state": "reused-state"})
    second = client.get("/apple-scim/callback", params={"code": "code-2", "state": "reused-state"})

    assert first.status_code == 200
    assert second.status_code == 400


def test_callback_502_network_error_contacting_apple(client, monkeypatch):
    import httpx

    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("net-error-state")
    monkeypatch.setattr(FakeAsyncClient, "raise_error", httpx.ConnectError("connection refused"))

    resp = client.get("/apple-scim/callback", params={"code": "some-code", "state": "net-error-state"})

    assert resp.status_code == 502


def test_callback_502_apple_rejects_code(client, monkeypatch):
    """Apple's token endpoint returning non-200 (e.g. an expired/invalid code) maps to 502."""
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("bad-code-state")
    monkeypatch.setattr(FakeAsyncClient, "response", FakeTokenResponse(400, {"error": "invalid_grant"}))

    resp = client.get("/apple-scim/callback", params={"code": "bad-code", "state": "bad-code-state"})

    assert resp.status_code == 502


def test_callback_502_missing_access_token(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("no-token-state")
    monkeypatch.setattr(FakeAsyncClient, "response", FakeTokenResponse(200, {"expires_in": 3600}))

    resp = client.get("/apple-scim/callback", params={"code": "some-code", "state": "no-token-state"})

    assert resp.status_code == 502


def test_callback_success_saves_tokens_and_returns_status(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("good-state")
    monkeypatch.setattr(
        FakeAsyncClient,
        "response",
        FakeTokenResponse(200, {"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600}),
    )

    resp = client.get("/apple-scim/callback", params={"code": "good-code", "state": "good-state"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "authorized"
    assert body["has_refresh_token"] is True
    assert body["expires_in"] == 3600
    assert FakeAsyncClient.last_request["data"]["grant_type"] == "authorization_code"
    assert FakeAsyncClient.last_request["data"]["code"] == "good-code"


def test_callback_invalid_expires_in_defaults_to_3600(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("weird-expiry-state")
    monkeypatch.setattr(
        FakeAsyncClient, "response", FakeTokenResponse(200, {"access_token": "tok", "expires_in": "not-a-number"})
    )

    resp = client.get("/apple-scim/callback", params={"code": "some-code", "state": "weird-expiry-state"})

    assert resp.status_code == 200
    assert resp.json()["expires_in"] == 3600


def test_callback_non_positive_expires_in_defaults_to_3600(client, monkeypatch):
    """expires_in that parses fine but is <= 0 is just as invalid as a non-numeric value."""
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("zero-expiry-state")
    monkeypatch.setattr(FakeAsyncClient, "response", FakeTokenResponse(200, {"access_token": "tok", "expires_in": 0}))

    resp = client.get("/apple-scim/callback", params={"code": "some-code", "state": "zero-expiry-state"})

    assert resp.status_code == 200
    assert resp.json()["expires_in"] == 3600


def test_callback_background_sync_failure_is_logged_not_raised(client, monkeypatch, caplog):
    """A failure in the fire-and-forget post-authorization sync must not affect the
    already-returned 200 response — it's only ever surfaced in logs."""
    import logging
    import time

    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("bg-failure-state")
    monkeypatch.setattr(
        FakeAsyncClient, "response", FakeTokenResponse(200, {"access_token": "tok", "expires_in": 3600})
    )

    async def _boom():
        raise RuntimeError("Authentik unreachable")

    monkeypatch.setattr(scim_routes, "get_users", _boom)

    with caplog.at_level(logging.ERROR, logger="app.routes.apple_scim"):
        resp = client.get("/apple-scim/callback", params={"code": "some-code", "state": "bg-failure-state"})
        # Let the fire-and-forget background task run on the TestClient's event loop.
        time.sleep(0.1)

    assert resp.status_code == 200
    assert "background sync after authorization failed" in caplog.text


def test_callback_background_sync_skipped_when_authentik_unavailable(client, monkeypatch):
    """get_users() returning None (Authentik unreachable, non-fatal) must skip sync_users
    without raising — the 200 response and token save already succeeded."""
    import time

    monkeypatch.setattr(scim_routes, "settings", _configured_settings())
    scim_routes._add_state("bg-skip-state")
    monkeypatch.setattr(
        FakeAsyncClient, "response", FakeTokenResponse(200, {"access_token": "tok", "expires_in": 3600})
    )

    sync_called = []

    async def _unavailable():
        return None

    async def _record_sync(access_token, scim_users):
        sync_called.append((access_token, scim_users))
        return SyncResult()

    monkeypatch.setattr(scim_routes, "get_users", _unavailable)
    monkeypatch.setattr(scim_routes, "sync_users", _record_sync)

    resp = client.get("/apple-scim/callback", params={"code": "some-code", "state": "bg-skip-state"})
    time.sleep(0.1)

    assert resp.status_code == 200
    assert sync_called == []


# ---------------------------------------------------------------------------
# GET /apple-scim/status
# ---------------------------------------------------------------------------


def test_status_requires_management_auth(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    resp = client.get("/apple-scim/status")

    assert resp.status_code == 401


def test_status_disabled_when_not_configured(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _disabled_settings())

    resp = client.get("/apple-scim/status", headers=MGMT_HEADERS)

    assert resp.status_code == 200
    assert resp.json() == {"enabled": False, "reason": "not_configured"}


def test_status_not_authorized_when_no_tokens_stored(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    async def _no_tokens():
        return None

    monkeypatch.setattr(scim_routes, "load_tokens", _no_tokens)

    resp = client.get("/apple-scim/status", headers=MGMT_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "enabled": True,
        "authorized": False,
        "reason": "Visit /apple-scim/authorize to connect",
    }


def test_status_authorized_and_token_still_valid(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings(apple_scim_alert_webhook_url="https://hook.test"))

    import time

    future = int(time.time()) + 3600

    async def _valid_tokens():
        return {
            "access_token": "tok",
            "refresh_token": "refresh",
            "expires_at": future,
            "updated_at": 1000,
        }

    monkeypatch.setattr(scim_routes, "load_tokens", _valid_tokens)

    resp = client.get("/apple-scim/status", headers=MGMT_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["authorized"] is True
    assert body["token_valid"] is True
    assert body["has_refresh_token"] is True
    assert body["alert_webhook_configured"] is True


def test_status_authorized_but_token_expired(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    async def _expired_tokens():
        return {
            "access_token": "tok",
            "refresh_token": None,
            "expires_at": 1,  # far in the past
            "updated_at": 1,
        }

    monkeypatch.setattr(scim_routes, "load_tokens", _expired_tokens)

    resp = client.get("/apple-scim/status", headers=MGMT_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert body["token_valid"] is False
    assert body["has_refresh_token"] is False
    assert body["token_expires_in_seconds"] == 0


# ---------------------------------------------------------------------------
# POST /apple-scim/sync
# ---------------------------------------------------------------------------


def test_sync_requires_management_auth(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    resp = client.post("/apple-scim/sync")

    assert resp.status_code == 401


def test_sync_503_when_not_configured(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _disabled_settings())

    resp = client.post("/apple-scim/sync", headers=MGMT_HEADERS)

    assert resp.status_code == 503


def test_sync_401_when_no_valid_access_token(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    async def _no_token():
        return None

    monkeypatch.setattr(scim_routes, "get_valid_access_token", _no_token)

    resp = client.post("/apple-scim/sync", headers=MGMT_HEADERS)

    assert resp.status_code == 401


def test_sync_502_when_authentik_users_unavailable(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    async def _has_token():
        return "valid-token"

    async def _authentik_down():
        return None

    monkeypatch.setattr(scim_routes, "get_valid_access_token", _has_token)
    monkeypatch.setattr(scim_routes, "get_users", _authentik_down)

    resp = client.post("/apple-scim/sync", headers=MGMT_HEADERS)

    assert resp.status_code == 502


def test_sync_502_when_apple_users_list_fails_with_network_error(client, monkeypatch):
    """A network error listing existing Apple users must surface as a clean 502, not an unhandled 500."""
    monkeypatch.setattr(scim_routes, "settings", _configured_settings())

    async def _has_token():
        return "valid-token"

    async def _users():
        return [{"userName": "a@example.com"}]

    async def _sync_network_error(access_token, scim_users):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(scim_routes, "get_valid_access_token", _has_token)
    monkeypatch.setattr(scim_routes, "get_users", _users)
    monkeypatch.setattr(scim_routes, "sync_users", _sync_network_error)

    resp = client.post("/apple-scim/sync", headers=MGMT_HEADERS)

    assert resp.status_code == 502
    assert "Could not reach Apple Business Manager" in resp.json()["detail"]


def test_sync_success_returns_result_summary(client, monkeypatch):
    monkeypatch.setattr(scim_routes, "settings", _configured_settings(apple_scim_update_mode="patch_all"))

    async def _has_token():
        return "valid-token"

    async def _users():
        return [{"userName": "a@example.com"}]

    async def _sync(access_token, scim_users):
        assert access_token == "valid-token"
        assert scim_users == [{"userName": "a@example.com"}]
        return SyncResult(
            created=1,
            updated=2,
            unchanged=3,
            conflicts=1,
            errors=0,
            update_400_invalid_request=0,
            out_of_scope_diffs=1,
        )

    monkeypatch.setattr(scim_routes, "get_valid_access_token", _has_token)
    monkeypatch.setattr(scim_routes, "get_users", _users)
    monkeypatch.setattr(scim_routes, "sync_users", _sync)

    resp = client.post("/apple-scim/sync", headers=MGMT_HEADERS)

    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "status": "ok",
        "created": 1,
        "updated": 2,
        "unchanged": 3,
        "conflicts": 1,
        "errors": 0,
        "update_400_invalid_request": 0,
        "out_of_scope_diffs": 1,
        "update_mode": "patch_all",
    }
    # conflict_usernames must never appear in the API response (PII).
    assert "conflict_usernames" not in body
