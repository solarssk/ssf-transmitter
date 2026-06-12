"""Tests for apple.py SCIM comparison logic (_users_differ, _primary_email)."""

from __future__ import annotations

import pytest

from app.scim.apple import (
    _can_recover_by_username,
    _format_changed_fields,
    _primary_email,
    _users_differ,
)

# ---------------------------------------------------------------------------
# _primary_email
# ---------------------------------------------------------------------------

class TestPrimaryEmail:
    def test_explicit_primary_true(self):
        user = {"emails": [{"value": "a@example.com", "primary": True}]}
        assert _primary_email(user) == "a@example.com"

    def test_no_primary_flag_falls_back_to_first(self):
        """Apple may omit primary flag — first email is the fallback."""
        user = {"emails": [{"value": "a@example.com"}, {"value": "b@example.com"}]}
        assert _primary_email(user) == "a@example.com"

    def test_primary_false_skipped_falls_back_to_first(self):
        user = {"emails": [{"value": "a@example.com", "primary": False}]}
        assert _primary_email(user) == "a@example.com"

    def test_no_emails_returns_none(self):
        assert _primary_email({}) is None
        assert _primary_email({"emails": []}) is None

    def test_mixed_primary_picks_true(self):
        user = {"emails": [
            {"value": "first@example.com", "primary": False},
            {"value": "primary@example.com", "primary": True},
        ]}
        assert _primary_email(user) == "primary@example.com"


# ---------------------------------------------------------------------------
# _users_differ
# ---------------------------------------------------------------------------

def _apple_user(
    username="user@example.com",
    given="John",
    family="Doe",
    active=True,
    email="user@example.com",
    email_primary=None,  # None = omit flag (simulates Apple response)
) -> dict:
    """Build a fake Apple SCIM GET response user.

    Set ``email_primary=None`` to simulate Apple omitting the ``primary`` flag
    (the common case that triggered the false-positive bug).
    """
    email_entry: dict = {"value": email}
    if email_primary is not None:
        email_entry["primary"] = email_primary
    return {
        "userName": username,
        "name": {"givenName": given, "familyName": family},
        "active": active,
        "emails": [email_entry],
    }


def _authentik_user(
    username="user@example.com",
    given="John",
    family="Doe",
    active=True,
    email="user@example.com",
) -> dict:
    """Build a fake Authentik → SCIM mapped user (always includes ``primary: true``)."""
    return {
        "userName": username,
        "name": {"givenName": given, "familyName": family},
        "active": active,
        "emails": [{"value": email, "primary": True, "type": "work"}],
    }


class TestUsersDiffer:
    def test_identical_no_diff(self):
        existing = _apple_user()
        new = _authentik_user()
        assert _users_differ(existing, new) is False

    def test_apple_omits_primary_flag_no_false_diff(self):
        """Core bug fix: Apple returns email without primary flag → must not diff."""
        existing = _apple_user(email_primary=None)  # Apple omits primary
        new = _authentik_user()                      # We always send primary=True
        assert _users_differ(existing, new) is False

    def test_apple_omits_active_no_false_diff(self):
        """Apple may omit active when True — should not be treated as changed."""
        existing = _apple_user()
        existing.pop("active")  # Apple omits the field
        new = _authentik_user(active=True)
        assert _users_differ(existing, new) is False

    def test_username_case_insensitive(self):
        """Apple may normalise userName to lowercase."""
        existing = _apple_user(username="user@example.com")
        new = _authentik_user(username="USER@example.com")
        assert _users_differ(existing, new) is False

    def test_given_name_changed(self):
        existing = _apple_user(given="John")
        new = _authentik_user(given="Jonathan")
        assert _users_differ(existing, new) is True

    def test_family_name_changed(self):
        existing = _apple_user(family="Doe")
        new = _authentik_user(family="Smith")
        assert _users_differ(existing, new) is True

    def test_email_changed(self):
        existing = _apple_user(email="old@example.com", email_primary=None)
        new = _authentik_user(email="new@example.com")
        assert _users_differ(existing, new) is True

    def test_active_changed_to_false(self):
        existing = _apple_user(active=True)
        new = _authentik_user(active=False)
        assert _users_differ(existing, new) is True

    def test_no_emails_in_apple_vs_email_in_new(self):
        """If Apple returns no emails at all, any email in new is a change."""
        existing = _apple_user()
        existing["emails"] = []
        new = _authentik_user(email="user@example.com")
        assert _users_differ(existing, new) is True

# ---------------------------------------------------------------------------
# _can_recover_by_username
# ---------------------------------------------------------------------------

class TestFormatChangedFields:
    def test_lists_changed_fields(self):
        assert _format_changed_fields({"email": True, "active": False, "userName": True}) == "email, userName"

    def test_none_when_empty(self):
        assert _format_changed_fields({"email": False, "active": False}) == "none"


class TestCanRecoverByUsername:
    def test_allows_missing_external_id(self):
        assert _can_recover_by_username({"userName": "a@example.com"}, "1") is True

    def test_allows_matching_external_id(self):
        apple_user = {"userName": "a@example.com", "externalId": "42"}
        assert _can_recover_by_username(apple_user, "42") is True

    def test_rejects_different_external_id(self):
        apple_user = {"userName": "a@example.com", "externalId": "17"}
        assert _can_recover_by_username(apple_user, "42") is False


# ---------------------------------------------------------------------------
# sync_users idempotence / externalId repair
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = b""
        self.text = ""
        self.headers = {}

    def json(self):
        return self._payload


class _FakeAppleClient:
    def __init__(
        self,
        timeout: float,
        *,
        apple_users: list[dict] | None = None,
        holder: dict | None = None,
    ):
        self.timeout = timeout
        self.apple_users = list(apple_users) if apple_users is not None else []
        self.requests: list[tuple[str, str, dict | None]] = []
        if holder is not None:
            holder["client"] = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers):
        self.requests.append(("GET", url, None))
        return _FakeResponse(200, {
            "Resources": self.apple_users,
            "totalResults": len(self.apple_users),
            "startIndex": 1,
            "itemsPerPage": len(self.apple_users),
        })

    async def post(self, url, json, headers):
        self.requests.append(("POST", url, json))
        created = {**json, "id": f"apple-{json['externalId']}"}
        self.apple_users.append(created)
        return _FakeResponse(201, created)

    async def put(self, url, json, headers):
        self.requests.append(("PUT", url, json))
        apple_id = url.rsplit("/", 1)[-1]
        for idx, user in enumerate(self.apple_users):
            if user.get("id") == apple_id:
                self.apple_users[idx] = {**json}
                return _FakeResponse(200, self.apple_users[idx])
        return _FakeResponse(404, {})

    async def patch(self, url, json, headers):
        self.requests.append(("PATCH", url, json))
        apple_id = url.rsplit("/", 1)[-1]
        for user in self.apple_users:
            if user.get("id") == apple_id:
                for op in json.get("Operations", []):
                    path = op.get("path")
                    if path:
                        user[path] = op.get("value")
                return _FakeResponse(200, user)
        return _FakeResponse(404, {})


def _install_fake_apple_client(monkeypatch, *, apple_users: list[dict] | None = None) -> dict:
    """Monkeypatch Apple httpx.AsyncClient with an isolated fake instance."""
    from app.scim import apple

    holder: dict[str, _FakeAppleClient] = {}
    shared_users = list(apple_users) if apple_users is not None else []

    class _BoundFakeAppleClient(_FakeAppleClient):
        def __init__(self, timeout: float):
            super().__init__(timeout, apple_users=shared_users, holder=holder)

    monkeypatch.setattr(apple.httpx, "AsyncClient", _BoundFakeAppleClient)
    return holder


def _apple_existing(external_id="1", username="user@example.com", email="user@example.com", primary=None):
    user = _apple_user(username=username, email=email, email_primary=primary)
    user["id"] = "apple-1"
    if external_id is not None:
        user["externalId"] = external_id
    return user


def _authentik_scim(external_id="1", username="user@example.com", email="user@example.com"):
    user = _authentik_user(username=username, email=email)
    user["externalId"] = external_id
    user["schemas"] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
    return user


@pytest.mark.anyio
async def test_sync_existing_same_email_in_emails_value_is_unchanged(monkeypatch):
    from app.scim import apple

    holder = _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing()])

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.unchanged == 1
    assert result.updated == 0
    assert [r[0] for r in holder["client"].requests] == ["GET"]


@pytest.mark.anyio
async def test_sync_existing_same_email_different_case_is_unchanged(monkeypatch):
    from app.scim import apple

    _install_fake_apple_client(
        monkeypatch,
        apple_users=[_apple_existing(username="USER@example.com", email="USER@example.com")],
    )

    result = await apple.sync_users("token", [_authentik_scim(username="user@example.com", email="user@example.com")])

    assert result.unchanged == 1
    assert result.updated == 0


@pytest.mark.anyio
async def test_sync_existing_changed_email_updates_once(monkeypatch):
    from app.scim import apple

    holder = _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(email="old@example.com")])

    result = await apple.sync_users("token", [_authentik_scim(email="new@example.com")])
    first_requests = list(holder["client"].requests)
    second = await apple.sync_users("token", [_authentik_scim(email="new@example.com")])
    all_requests = first_requests + holder["client"].requests

    assert result.updated == 1
    assert second.unchanged == 1
    assert any(method == "PATCH" for method, _, _ in all_requests)


@pytest.mark.anyio
async def test_sync_skips_username_match_with_different_external_id(monkeypatch):
    from app.scim import apple

    holder = _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(external_id="99")])

    result = await apple.sync_users("token", [_authentik_scim(external_id="1")])

    assert result.updated == 0
    assert result.created == 1
    methods = [r[0] for r in holder["client"].requests]
    assert "PATCH" not in methods
    assert "PUT" not in methods
    assert methods == ["GET", "POST"]


@pytest.mark.anyio
async def test_sync_recovered_by_username_missing_external_id_patches_once_then_unchanged(monkeypatch):
    from app.scim import apple

    holder = _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(external_id=None)])

    first = await apple.sync_users("token", [_authentik_scim(external_id="1")])
    first_requests = list(holder["client"].requests)
    second = await apple.sync_users("token", [_authentik_scim(external_id="1")])
    methods = [r[0] for r in first_requests + holder["client"].requests]
    assert first.updated == 1
    assert second.unchanged == 1
    assert methods.count("PATCH") == 1


def test_primary_email_prefers_primary_when_multiple_emails():
    user = {"emails": [
        {"value": "alias@example.com", "primary": False},
        {"value": "primary@example.com", "primary": True},
    ]}
    assert _primary_email(user) == "primary@example.com"


def test_email_whitespace_and_case_do_not_diff():
    existing = _apple_user(email=" USER@example.com ")
    new = _authentik_user(email="user@example.com")
    assert _users_differ(existing, new) is False
