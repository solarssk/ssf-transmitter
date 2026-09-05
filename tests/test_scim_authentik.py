from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import ClassVar

import httpx
import pytest

from app.scim import authentik


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, *, bad_json: bool = False):
        self.status_code = status_code
        self._payload = payload or {}
        self._bad_json = bad_json
        self.content = b""
        self.text = ""
        self.headers = {}

    def json(self):
        if self._bad_json:
            raise ValueError("not valid JSON")
        return self._payload


class FakeAsyncClient:
    # Deliberately class-level, not per-instance — see test_pusher.py's
    # FakeAsyncClient for why (tests monkeypatch these directly on the class).
    requests: ClassVar[list[str]] = []
    responses: ClassVar[list[FakeResponse]] = []
    raise_network_error: ClassVar[bool] = False

    def __init__(self, timeout: float):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers):
        if self.raise_network_error:
            raise httpx.ConnectError("connection refused")
        self.requests.append(url)
        return self.responses.pop(0)


def _settings(group_id: str | None = None):
    return SimpleNamespace(
        authentik_url="https://authentik.example.test",
        authentik_token="token",
        apple_scim_group_id=group_id,
    )


def _user(pk: int, email: str, name: str = "User Example") -> dict:
    return {"pk": pk, "email": email, "name": name, "is_active": True}


@pytest.mark.anyio
async def test_no_group_filter_active_users_are_considered(monkeypatch):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(
        FakeAsyncClient, "responses", [FakeResponse(200, {"results": [_user(1, "a@example.com")], "next": None})]
    )
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings())

    users = await authentik.get_users()

    assert [u["externalId"] for u in users] == ["1"]
    assert FakeAsyncClient.requests == ["https://authentik.example.test/api/v3/core/users/?type=internal&page_size=500"]


@pytest.mark.anyio
async def test_group_filter_fetches_only_group_members(monkeypatch):
    group_id = "978bff1a-5f55-4068-808c-45e09bb196d4"
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(
        FakeAsyncClient, "responses", [FakeResponse(200, {"results": [_user(2, "member@example.com")], "next": None})]
    )
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    users = await authentik.get_users()

    assert [u["userName"] for u in users] == ["member@example.com"]
    assert FakeAsyncClient.requests == [
        f"https://authentik.example.test/api/v3/core/users/?groups_by_pk={group_id}&type=internal&page_size=500"
    ]


@pytest.mark.anyio
async def test_user_without_email_outside_group_is_never_logged(monkeypatch, caplog):
    group_id = "978bff1a-5f55-4068-808c-45e09bb196d4"
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(
        FakeAsyncClient, "responses", [FakeResponse(200, {"results": [_user(2, "member@example.com")], "next": None})]
    )
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    with caplog.at_level(logging.WARNING, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert len(users) == 1
    assert "pk=66 (no email)" not in caplog.text


@pytest.mark.anyio
async def test_user_without_email_inside_group_is_skipped_with_clear_error(monkeypatch, caplog):
    group_id = "978bff1a-5f55-4068-808c-45e09bb196d4"
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "responses", [FakeResponse(200, {"results": [_user(66, "")], "next": None})])
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users == []
    assert "skipping Authentik user pk=66 (no email)" in caplog.text


@pytest.mark.anyio
async def test_group_filter_auth_failure_fails_clearly(monkeypatch, caplog):
    group_id = "978bff1a-5f55-4068-808c-45e09bb196d4"
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "responses", [FakeResponse(403, {})])
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users is None
    assert f"APPLE_SCIM_GROUP_ID={group_id} could not be read" in caplog.text


@pytest.mark.anyio
async def test_no_group_filter_error_response_logs_generic_message(monkeypatch, caplog):
    """A non-200 with no group filter configured hits _log_page_error's generic (non-403-group) branch."""
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "responses", [FakeResponse(500, {})])
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings())

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users is None
    assert "Authentik API error response=" in caplog.text


@pytest.mark.anyio
async def test_non_json_response_is_treated_as_error(monkeypatch, caplog):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "responses", [FakeResponse(200, bad_json=True)])
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings())

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users is None
    assert "Authentik API returned non-JSON response=" in caplog.text


@pytest.mark.anyio
async def test_network_error_is_treated_as_error(monkeypatch, caplog):
    monkeypatch.setattr(FakeAsyncClient, "raise_network_error", True)
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings())

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users is None
    assert "Failed to fetch users from Authentik" in caplog.text
    monkeypatch.setattr(FakeAsyncClient, "raise_network_error", False)


@pytest.mark.anyio
async def test_user_with_missing_pk_is_skipped(monkeypatch, caplog):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(
        FakeAsyncClient,
        "responses",
        [FakeResponse(200, {"results": [{"pk": None, "email": "a@example.com", "name": "A"}], "next": None})],
    )
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings())

    with caplog.at_level(logging.WARNING, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users == []
    assert "skipping Authentik user with missing pk" in caplog.text


@pytest.mark.anyio
async def test_user_with_blank_name_warns_but_is_still_synced(monkeypatch, caplog):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(
        FakeAsyncClient,
        "responses",
        [FakeResponse(200, {"results": [_user(5, "noname@example.com", name="  ")], "next": None})],
    )
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings())

    with caplog.at_level(logging.WARNING, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert [u["externalId"] for u in users] == ["5"]
    assert "has no display name — givenName will be empty" in caplog.text


@pytest.mark.parametrize("field", ["authentik_url", "authentik_token"])
@pytest.mark.anyio
async def test_get_users_not_configured_returns_none(monkeypatch, caplog, field):
    settings = _settings()
    setattr(settings, field, "")
    monkeypatch.setattr(authentik, "settings", settings)

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users is None
    assert "Authentik URL or token not configured" in caplog.text
