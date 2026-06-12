from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from app.scim import authentik


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = b""
        self.text = ""
        self.headers = {}

    def json(self):
        return self._payload


class FakeAsyncClient:
    requests: list[str] = []
    responses: list[FakeResponse] = []

    def __init__(self, timeout: float):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers):
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
    FakeAsyncClient.requests = []
    FakeAsyncClient.responses = [FakeResponse(200, {"results": [_user(1, "a@example.com")], "next": None})]
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings())

    users = await authentik.get_users()

    assert [u["externalId"] for u in users] == ["1"]
    assert FakeAsyncClient.requests == [
        "https://authentik.example.test/api/v3/core/users/?type=internal&page_size=500"
    ]


@pytest.mark.anyio
async def test_group_filter_fetches_only_group_members(monkeypatch):
    group_id = "978bff1a-5f55-4068-808c-45e09bb196d4"
    FakeAsyncClient.requests = []
    FakeAsyncClient.responses = [FakeResponse(200, {"results": [_user(2, "member@example.com")], "next": None})]
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    users = await authentik.get_users()

    assert [u["userName"] for u in users] == ["member@example.com"]
    assert FakeAsyncClient.requests == [
        f"https://authentik.example.test/api/v3/core/groups/{group_id}/users/?type=internal&page_size=500"
    ]


@pytest.mark.anyio
async def test_user_without_email_outside_group_is_never_logged(monkeypatch, caplog):
    group_id = "978bff1a-5f55-4068-808c-45e09bb196d4"
    FakeAsyncClient.requests = []
    FakeAsyncClient.responses = [FakeResponse(200, {"results": [_user(2, "member@example.com")], "next": None})]
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    with caplog.at_level(logging.WARNING, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert len(users) == 1
    assert "pk=66 (no email)" not in caplog.text


@pytest.mark.anyio
async def test_user_without_email_inside_group_is_skipped_with_clear_error(monkeypatch, caplog):
    group_id = "978bff1a-5f55-4068-808c-45e09bb196d4"
    FakeAsyncClient.requests = []
    FakeAsyncClient.responses = [FakeResponse(200, {"results": [_user(66, "")], "next": None})]
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users == []
    assert "skipping Authentik user pk=66 (no email)" in caplog.text


@pytest.mark.anyio
async def test_invalid_group_id_fails_clearly(monkeypatch, caplog):
    group_id = "missing-group"
    FakeAsyncClient.requests = []
    FakeAsyncClient.responses = [FakeResponse(404, {})]
    monkeypatch.setattr(authentik.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(authentik, "settings", _settings(group_id))

    with caplog.at_level(logging.ERROR, logger="app.scim.authentik"):
        users = await authentik.get_users()

    assert users is None
    assert "APPLE_SCIM_GROUP_ID=missing-group could not be read" in caplog.text
