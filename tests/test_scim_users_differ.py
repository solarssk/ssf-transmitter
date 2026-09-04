"""Tests for apple.py SCIM comparison logic (_users_differ, _primary_email)."""

from __future__ import annotations

import dataclasses

import pytest

from app.config import settings as real_settings
from app.scim.apple import (
    _actionable_diffs,
    _build_update_request,
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
        user = {
            "emails": [
                {"value": "first@example.com", "primary": False},
                {"value": "primary@example.com", "primary": True},
            ]
        }
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
        new = _authentik_user()  # We always send primary=True
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


class TestBuildUpdateRequest:
    def test_patch_all_mode_builds_patch_operations(self):
        user = _authentik_user()
        user["externalId"] = "42"
        method, body, fields = _build_update_request(user, "patch_all", "apple-1")
        assert method == "PATCH"
        assert fields == ["externalId", "userName", "name", "emails", "active"]
        assert [op["path"] for op in body["Operations"]] == fields

    def test_external_id_only_mode_builds_single_operation(self):
        user = _authentik_user()
        user["externalId"] = "42"
        method, body, fields = _build_update_request(user, "external_id_only", "apple-1")
        assert method == "PATCH"
        assert fields == ["externalId"]
        assert body["Operations"] == [{"op": "Replace", "path": "externalId", "value": "42"}]

    def test_replace_all_mode_builds_put(self):
        """Apple rejects a PUT body containing `externalId` (immutable) or
        missing the resource `id` — regression test for a real bug where
        this mode sent the raw Authentik-mapped dict (externalId present,
        no id) and every replace_all-mode update permanently failed."""
        user = _authentik_user()
        user["externalId"] = "42"
        method, body, fields = _build_update_request(user, "replace_all", "apple-1")
        assert method == "PUT"
        assert "externalId" not in body
        assert body["id"] == "apple-1"
        assert body["userName"] == user["userName"]
        assert body["emails"] == user["emails"]
        assert fields == ["externalId", "userName", "name", "emails", "active"]


class TestActionableDiffs:
    """A diff outside update_mode's scope can never be fixed by _patch_user() —
    treating it as actionable would re-trigger the same no-op PATCH forever."""

    def test_patch_all_mode_keeps_every_diff(self):
        diffs = {"email": True, "userName": False, "externalId": True}
        assert _actionable_diffs(diffs, "patch_all") == diffs

    def test_external_id_only_mode_drops_out_of_scope_diffs(self):
        diffs = {"email": True, "userName": False, "externalId": False}
        assert _actionable_diffs(diffs, "external_id_only") == {"externalId": False}

    def test_emails_only_mode_maps_email_key(self):
        diffs = {"email": True, "externalId": True}
        assert _actionable_diffs(diffs, "emails_only") == {"email": True}

    def test_username_only_mode_maps_username_key(self):
        diffs = {"userName": True, "email": True}
        assert _actionable_diffs(diffs, "username_only") == {"userName": True}

    def test_replace_all_mode_covers_name_split_fields(self):
        diffs = {"givenName": True, "familyName": False, "email": True}
        assert _actionable_diffs(diffs, "replace_all") == diffs


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
        return _FakeResponse(
            200,
            {
                "Resources": self.apple_users,
                "totalResults": len(self.apple_users),
                "startIndex": 1,
                "itemsPerPage": len(self.apple_users),
            },
        )

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
    user = {
        "emails": [
            {"value": "alias@example.com", "primary": False},
            {"value": "primary@example.com", "primary": True},
        ]
    }
    assert _primary_email(user) == "primary@example.com"


def test_email_whitespace_and_case_do_not_diff():
    existing = _apple_user(email=" USER@example.com ")
    new = _authentik_user(email="user@example.com")
    assert _users_differ(existing, new) is False


@pytest.mark.anyio
async def test_sync_external_id_only_mode_does_not_loop_on_unfixable_email_diff(monkeypatch):
    """Regression test for a real production bug: with update_mode=external_id_only,
    an already-linked user whose email differs was detected as "changed" every
    sync (since _field_diffs compares all fields), but _patch_user only ever
    wrote externalId back — so the email diff was never actually resolved and
    the same no-op PATCH fired again on every subsequent sync, forever.
    """
    from app.scim import apple

    scoped_settings = dataclasses.replace(real_settings, apple_scim_update_mode="external_id_only")
    monkeypatch.setattr(apple, "settings", scoped_settings)
    holder = _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(email="stale@example.com")])

    first = await apple.sync_users("token", [_authentik_scim(email="fresh@example.com")])
    first_requests = list(holder["client"].requests)
    second = await apple.sync_users("token", [_authentik_scim(email="fresh@example.com")])

    # The email diff is outside external_id_only's scope and can never be
    # fixed by this update_mode, so it must not be treated as "needs update"
    # — no PATCH should ever fire for it, on either sync.
    assert first.unchanged == 1
    assert first.updated == 0
    assert first.out_of_scope_diffs == 1
    assert second.unchanged == 1
    assert second.updated == 0
    assert second.out_of_scope_diffs == 1
    assert all(method == "GET" for method, _, _ in first_requests + holder["client"].requests)


@pytest.mark.anyio
async def test_handle_409_external_id_only_mode_does_not_loop_on_unfixable_email_diff(monkeypatch):
    """Same regression as above, but through the 409-recovery path
    (_handle_409), which has its own copy of the actionable-diffs decision
    and was not exercised by the sync_users()-level test above.
    """
    from app.scim import apple

    scoped_settings = dataclasses.replace(real_settings, apple_scim_update_mode="external_id_only")
    monkeypatch.setattr(apple, "settings", scoped_settings)

    found = _apple_existing(email="stale@example.com")
    fake_client = _FakeAppleClient(30.0, apple_users=[found])
    new_user = _authentik_scim(email="fresh@example.com")
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, new_user, result)

    assert result.unchanged == 1
    assert result.updated == 0
    assert result.out_of_scope_diffs == 1
    assert result.conflicts == 0
    assert all(method == "GET" for method, _, _ in fake_client.requests)


@pytest.mark.anyio
async def test_handle_409_patches_actionable_diff():
    """The other side of the same branch: under the default patch_all mode
    (no narrow update_mode scoping), a real diff found via 409-recovery
    must still result in a PATCH, not be treated as out-of-scope."""
    from app.scim import apple

    found = _apple_existing(email="stale@example.com")
    fake_client = _FakeAppleClient(30.0, apple_users=[found])
    new_user = _authentik_scim(email="fresh@example.com")
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, new_user, result)

    assert result.updated == 1
    assert result.unchanged == 0
    assert result.out_of_scope_diffs == 0
    assert any(method == "PATCH" for method, _, _ in fake_client.requests)
