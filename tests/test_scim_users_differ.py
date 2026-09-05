"""Tests for apple.py SCIM comparison logic (_users_differ, _primary_email)."""

from __future__ import annotations

import dataclasses
import logging

import httpx
import pytest

from app.config import settings as real_settings
from app.scim import apple
from app.scim.apple import (
    _actionable_diffs,
    _build_update_request,
    _can_recover_by_username,
    _classify_update_400,
    _format_changed_fields,
    _index_users_page,
    _next_users_page_url,
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

    def test_emails_as_single_dict_is_wrapped_in_a_list(self):
        """Malformed input: a single dict instead of a list — wrap and use it."""
        user = {"emails": {"value": "solo@example.com", "primary": True}}
        assert _primary_email(user) == "solo@example.com"

    def test_emails_wrong_type_returns_none(self):
        """emails is neither a list nor a dict (e.g. a bare string) — ignored safely."""
        assert _primary_email({"emails": "not-a-list"}) is None

    def test_non_dict_email_entry_is_skipped(self):
        """A malformed (non-dict) entry in the emails list is skipped, not crashed on."""
        user = {"emails": ["not-a-dict", {"value": "real@example.com", "primary": True}]}
        assert _primary_email(user) == "real@example.com"


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


class _BadJsonResponse:
    """A response whose .json() raises — distinct from _FakeResponse(bad_json=True)
    so this module's pure-function tests don't depend on the sync-level fixture below."""

    status_code = 400

    def json(self):
        raise ValueError("not valid JSON")


class TestClassifyUpdate400:
    def test_non_400_status_is_never_classified(self):
        resp = _BadJsonResponse()
        resp.status_code = 500
        assert _classify_update_400(resp) is False

    def test_400_with_non_json_body_is_classified(self):
        assert _classify_update_400(_BadJsonResponse()) is True

    def test_400_with_dict_body_missing_known_keys_is_still_classified(self):
        class _Resp:
            status_code = 400

            def json(self):
                return {"unexpected": "shape"}

        assert _classify_update_400(_Resp()) is True

    def test_400_with_scim_type_is_classified(self):
        class _Resp:
            status_code = 400

            def json(self):
                return {"scimType": "invalidValue"}

        assert _classify_update_400(_Resp()) is True


class TestIndexUsersPage:
    def test_resource_without_username_is_not_indexed_by_username(self):
        by_ext_id: dict = {}
        by_username: dict = {}
        _index_users_page({"Resources": [{"externalId": "1"}]}, by_ext_id, by_username)
        assert by_ext_id == {"1": {"externalId": "1"}}
        assert by_username == {}


class TestNextUsersPageUrl:
    def test_empty_page_with_positive_total_does_not_loop_forever(self):
        """Guard: itemsPerPage=0 with totalResults > 0 must stop pagination, not spin."""
        data = {"totalResults": 5, "startIndex": 1, "itemsPerPage": 0, "Resources": []}
        assert _next_users_page_url(data) is None

    def test_more_pages_remain_returns_next_start_index(self):
        from app.scim.apple import APPLE_SCIM_BASE

        data = {"totalResults": 5, "startIndex": 1, "itemsPerPage": 2, "Resources": [{}, {}]}
        assert _next_users_page_url(data) == f"{APPLE_SCIM_BASE}/Users?count=200&startIndex=3"

    def test_last_page_returns_none(self):
        data = {"totalResults": 2, "startIndex": 1, "itemsPerPage": 2, "Resources": [{}, {}]}
        assert _next_users_page_url(data) is None


# ---------------------------------------------------------------------------
# sync_users idempotence / externalId repair
# ---------------------------------------------------------------------------


class _FakeResponse:
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


class _FakeAppleClient:
    def __init__(
        self,
        timeout: float,
        *,
        apple_users: list[dict] | None = None,
        holder: dict | None = None,
        fail_external_id_patch: bool = False,
        external_id_patch_status: int = 400,
        fail_patch: bool = False,
        fail_patch_status: int = 500,
        fail_create: bool = False,
        simulate_409: bool = False,
        raise_network_error: bool = False,
        list_failure: str | None = None,
        filter_failure: str | None = None,
    ):
        self.timeout = timeout
        self.apple_users = list(apple_users) if apple_users is not None else []
        self.requests: list[tuple[str, str, dict | None]] = []
        self.fail_external_id_patch = fail_external_id_patch
        self.external_id_patch_status = external_id_patch_status
        self.fail_patch = fail_patch
        self.fail_patch_status = fail_patch_status
        self.fail_create = fail_create
        self.simulate_409 = simulate_409
        self.raise_network_error = raise_network_error
        self.list_failure = list_failure
        self.filter_failure = filter_failure
        if holder is not None:
            holder["client"] = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers):
        self.requests.append(("GET", url, None))
        failure = self.filter_failure if "filter=" in url else self.list_failure
        if failure == "network":
            raise httpx.ConnectError("connection refused")
        if failure == "non_200":
            return _FakeResponse(500, {})
        if failure == "bad_json":
            return _FakeResponse(200, bad_json=True)
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
        if self.raise_network_error:
            raise httpx.ConnectError("connection refused")
        if self.fail_create:
            return _FakeResponse(500, {})
        if self.simulate_409:
            return _FakeResponse(409, {"scimType": "uniqueness"})
        created = {**json, "id": f"apple-{json['externalId']}"}
        self.apple_users.append(created)
        return _FakeResponse(201, created)

    async def put(self, url, json, headers):
        self.requests.append(("PUT", url, json))
        apple_id = url.rsplit("/", 1)[-1]
        for user in self.apple_users:
            if user.get("id") == apple_id:
                # Mutate the existing dict in place (matching patch() below)
                # rather than rebinding this list slot to a new dict — a
                # fresh _FakeAppleClient for a later sync_users() call holds
                # its own shallow-copied `apple_users` list, so a rebind here
                # would silently not propagate to it, only an in-place
                # mutation of the shared dict object would.
                external_id = user.get("externalId")
                user.clear()
                user.update(json)
                # Real Apple SCIM treats externalId as immutable-after-creation
                # and rejects a PUT body that includes it (see
                # _build_update_request's replace_all mode) — it does not get
                # cleared server-side just because a PUT omits it.
                if "externalId" not in user and external_id is not None:
                    user["externalId"] = external_id
                return _FakeResponse(200, user)
        return _FakeResponse(404, {})

    async def patch(self, url, json, headers):
        self.requests.append(("PATCH", url, json))
        ops = json.get("Operations", [])
        is_external_id_repair = len(ops) == 1 and ops[0].get("path") == "externalId"
        if is_external_id_repair and self.fail_external_id_patch:
            return _FakeResponse(self.external_id_patch_status, {"scimType": "invalidValue"})
        if not is_external_id_repair and self.fail_patch:
            return _FakeResponse(self.fail_patch_status, {"scimType": "invalidValue"})
        apple_id = url.rsplit("/", 1)[-1]
        for user in self.apple_users:
            if user.get("id") == apple_id:
                for op in ops:
                    path = op.get("path")
                    if path:
                        user[path] = op.get("value")
                return _FakeResponse(200, user)
        return _FakeResponse(404, {})


def _install_fake_apple_client(
    monkeypatch,
    *,
    apple_users: list[dict] | None = None,
    fail_external_id_patch: bool = False,
    external_id_patch_status: int = 400,
    fail_patch: bool = False,
    fail_patch_status: int = 500,
    fail_create: bool = False,
    simulate_409: bool = False,
    raise_network_error: bool = False,
) -> dict:
    """Monkeypatch Apple httpx.AsyncClient with an isolated fake instance."""
    holder: dict[str, _FakeAppleClient] = {}
    shared_users = list(apple_users) if apple_users is not None else []

    class _BoundFakeAppleClient(_FakeAppleClient):
        def __init__(self, timeout: float):
            super().__init__(
                timeout,
                apple_users=shared_users,
                holder=holder,
                fail_external_id_patch=fail_external_id_patch,
                external_id_patch_status=external_id_patch_status,
                fail_patch=fail_patch,
                fail_patch_status=fail_patch_status,
                fail_create=fail_create,
                simulate_409=simulate_409,
                raise_network_error=raise_network_error,
            )

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


@pytest.mark.anyio
async def test_sync_recovered_by_username_repairs_external_id_even_with_other_diffs(monkeypatch):
    """Regression test: externalId repair used to be gated on "no other
    field differs" — under replace_all mode the PUT it falls through to
    never includes externalId (Apple rejects it there), so a user missing
    externalId AND with e.g. a changed email would have linkage stay
    broken for a whole extra sync cycle even though the email got fixed.
    """
    from app.scim import apple

    scoped_settings = dataclasses.replace(real_settings, apple_scim_update_mode="replace_all")
    monkeypatch.setattr(apple, "settings", scoped_settings)
    holder = _install_fake_apple_client(
        monkeypatch, apple_users=[_apple_existing(external_id=None, email="stale@example.com")]
    )

    first = await apple.sync_users("token", [_authentik_scim(external_id="1", email="fresh@example.com")])
    first_methods = [r[0] for r in holder["client"].requests]
    second = await apple.sync_users("token", [_authentik_scim(external_id="1", email="fresh@example.com")])

    # Two real writes happened — the dedicated externalId repair (PATCH) and
    # the replace_all email update (PUT) — each counted independently.
    assert first.updated == 2
    assert "PATCH" in first_methods  # the dedicated externalId repair
    assert "PUT" in first_methods  # the replace_all update for email
    # Both repaired in one pass — the second sync must find nothing left to fix.
    assert second.unchanged == 1
    assert second.updated == 0
    assert second.out_of_scope_diffs == 0


@pytest.mark.anyio
async def test_sync_reports_out_of_scope_diff_alongside_actionable_update(monkeypatch):
    """Regression test: out_of_scope_diffs was only counted when there was
    NO actionable diff at all. A user with BOTH an actionable diff (email,
    in scope for emails_only) AND an out-of-scope one (name) had the name
    diff silently dropped from the count — the response/warning reported
    zero until a later sync saw the name diff alone.
    """
    from app.scim import apple

    scoped_settings = dataclasses.replace(real_settings, apple_scim_update_mode="emails_only")
    monkeypatch.setattr(apple, "settings", scoped_settings)
    existing = _apple_user(given="OldName", email="stale@example.com")
    existing["id"] = "apple-1"
    existing["externalId"] = "1"
    new_user = _authentik_user(given="NewName", email="fresh@example.com")
    new_user["externalId"] = "1"
    new_user["schemas"] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
    _install_fake_apple_client(monkeypatch, apple_users=[existing])

    result = await apple.sync_users("token", [new_user])

    assert result.updated == 1  # email patched (in scope for emails_only)
    assert result.out_of_scope_diffs == 1  # name diff reported, not silently dropped
    assert result.unchanged == 0


@pytest.mark.anyio
async def test_handle_409_reports_out_of_scope_diff_alongside_actionable_update():
    """Same regression as above, through the 409-recovery path."""
    from app.scim import apple

    found = _apple_user(given="OldName", email="stale@example.com")
    found["id"] = "apple-1"
    found["externalId"] = "1"
    new_user = _authentik_user(given="NewName", email="fresh@example.com")
    new_user["externalId"] = "1"
    fake_client = _FakeAppleClient(30.0, apple_users=[found])
    result = apple.SyncResult()

    with pytest.MonkeyPatch.context() as mp:
        scoped_settings = dataclasses.replace(real_settings, apple_scim_update_mode="emails_only")
        mp.setattr(apple, "settings", scoped_settings)
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.updated == 1
    assert result.out_of_scope_diffs == 1
    assert result.unchanged == 0


@pytest.mark.anyio
async def test_sync_failed_external_id_repair_is_not_also_counted_unchanged(monkeypatch):
    """Regression test: a failed externalId repair PATCH is already counted
    via result.errors (inside _patch_external_id) — the caller used to also
    increment result.unchanged whenever external_id_patched was falsy,
    which conflated "no repair needed" with "repair needed and failed",
    double-counting the same user into two mutually-exclusive buckets.
    """
    from app.scim import apple

    holder = _install_fake_apple_client(
        monkeypatch,
        apple_users=[_apple_existing(external_id=None)],  # linkage lost, everything else matches
        fail_external_id_patch=True,
    )

    result = await apple.sync_users("token", [_authentik_scim(external_id="1")])

    assert result.errors == 1
    assert result.unchanged == 0
    assert result.updated == 0
    assert all(method != "PUT" for method, _, _ in holder["client"].requests)


@pytest.mark.anyio
async def test_handle_409_failed_external_id_repair_is_not_also_counted_unchanged():
    """Same regression as above, through the 409-recovery path."""
    from app.scim import apple

    found = _apple_existing(external_id=None)
    fake_client = _FakeAppleClient(30.0, apple_users=[found], fail_external_id_patch=True)
    new_user = _authentik_scim(external_id="1")
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, new_user, result)

    assert result.errors == 1
    assert result.unchanged == 0
    assert result.updated == 0


# ---------------------------------------------------------------------------
# _get_existing_users: upstream listing failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_get_existing_users_non_200_response_returns_empty(caplog):
    from app.scim import apple

    fake_client = _FakeAppleClient(30.0, list_failure="non_200")

    with caplog.at_level(logging.ERROR, logger="app.scim.apple"):
        by_ext_id, by_username = await apple._get_existing_users(fake_client, {})

    assert (by_ext_id, by_username) == ({}, {})
    assert "Apple SCIM list users failed" in caplog.text


@pytest.mark.anyio
async def test_get_existing_users_non_json_response_returns_empty(caplog):
    from app.scim import apple

    fake_client = _FakeAppleClient(30.0, list_failure="bad_json")

    with caplog.at_level(logging.ERROR, logger="app.scim.apple"):
        by_ext_id, by_username = await apple._get_existing_users(fake_client, {})

    assert (by_ext_id, by_username) == ({}, {})
    assert "non-JSON response" in caplog.text


# ---------------------------------------------------------------------------
# _query_username_filter (via _handle_409): upstream filter-query failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_handle_409_filter_query_network_error_is_a_conflict(caplog):
    fake_client = _FakeAppleClient(30.0, apple_users=[], filter_failure="network")
    new_user = _authentik_scim()
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.conflicts == 1
    assert "409-recovery network error" in caplog.text


@pytest.mark.anyio
async def test_handle_409_filter_query_non_200_is_a_conflict(caplog):
    fake_client = _FakeAppleClient(30.0, apple_users=[], filter_failure="non_200")
    new_user = _authentik_scim()
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.conflicts == 1
    assert "409-recovery filter query failed" in caplog.text


@pytest.mark.anyio
async def test_handle_409_filter_query_non_json_is_a_conflict(caplog):
    fake_client = _FakeAppleClient(30.0, apple_users=[], filter_failure="bad_json")
    new_user = _authentik_scim()
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.conflicts == 1
    assert "409-recovery filter query returned non-JSON" in caplog.text


# ---------------------------------------------------------------------------
# _handle_409: no match / mismatched-owner outcomes
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_handle_409_no_match_found_is_a_conflict(caplog):
    """The filter query succeeds but returns zero Resources — nothing to recover."""
    fake_client = _FakeAppleClient(30.0, apple_users=[])
    new_user = _authentik_scim()
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.conflicts == 1
    assert result.conflict_usernames == [new_user["userName"]]
    assert "USERNAME_CONFLICT" in caplog.text


@pytest.mark.anyio
async def test_handle_409_matched_record_belongs_to_different_user_is_a_conflict(caplog):
    """The filter query finds a record, but it belongs to a different externalId — must not adopt it."""
    found = _apple_existing(external_id="99")
    fake_client = _FakeAppleClient(30.0, apple_users=[found])
    new_user = _authentik_scim(external_id="1")
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.conflicts == 1
    assert result.updated == 0
    assert "belonging to a different user" in caplog.text
    assert "USERNAME_CONFLICT" in caplog.text


# ---------------------------------------------------------------------------
# _match_apple_user: no match at all (empty Apple directory)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_sync_creates_user_when_apple_directory_is_empty(monkeypatch):
    """Neither an externalId match nor a username match exists at all — straight to create."""
    holder = _install_fake_apple_client(monkeypatch, apple_users=[])

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.created == 1
    assert [r[0] for r in holder["client"].requests] == ["GET", "POST"]


# ---------------------------------------------------------------------------
# _patch_user / _log_update_failure: a normal (non-external-id-repair) PATCH failure
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_sync_update_failure_counts_error_not_classified_as_400(monkeypatch):
    """A non-400 update failure is counted as an error but not as update_400_invalid_request."""
    _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(email="stale@example.com")], fail_patch=True)

    result = await apple.sync_users("token", [_authentik_scim(email="fresh@example.com")])

    assert result.errors == 1
    assert result.updated == 0
    assert result.update_400_invalid_request == 0


@pytest.mark.anyio
async def test_sync_update_failure_400_is_classified(monkeypatch):
    """A 400 update failure IS counted as update_400_invalid_request."""
    _install_fake_apple_client(
        monkeypatch,
        apple_users=[_apple_existing(email="stale@example.com")],
        fail_patch=True,
        fail_patch_status=400,
    )

    result = await apple.sync_users("token", [_authentik_scim(email="fresh@example.com")])

    assert result.errors == 1
    assert result.update_400_invalid_request == 1


@pytest.mark.anyio
async def test_update_failure_includes_response_body_when_enabled(monkeypatch, caplog):
    """APPLE_SCIM_LOG_ERROR_BODY=true includes the (redacted) response body in the failure log."""
    scoped_settings = dataclasses.replace(real_settings, apple_scim_log_error_body=True)
    monkeypatch.setattr(apple, "settings", scoped_settings)
    _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(email="stale@example.com")], fail_patch=True)

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        result = await apple.sync_users("token", [_authentik_scim(email="fresh@example.com")])

    assert result.errors == 1
    assert "redacted_body=" in caplog.text


# ---------------------------------------------------------------------------
# _patch_external_id: a non-400 failure is not classified as update_400_invalid_request
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_external_id_repair_non_400_failure_not_classified(monkeypatch):
    _install_fake_apple_client(
        monkeypatch,
        apple_users=[_apple_existing(external_id=None)],
        fail_external_id_patch=True,
        external_id_patch_status=500,
    )

    result = await apple.sync_users("token", [_authentik_scim(external_id="1")])

    assert result.errors == 1
    assert result.update_400_invalid_request == 0


# ---------------------------------------------------------------------------
# _create_user: a general (non-409) create failure
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_sync_create_failure_counts_error(monkeypatch):
    holder = _install_fake_apple_client(monkeypatch, apple_users=[], fail_create=True)

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.errors == 1
    assert result.created == 0
    assert [r[0] for r in holder["client"].requests] == ["GET", "POST"]


# ---------------------------------------------------------------------------
# sync_users: unresolvable 409 conflict surfaces in the sync-done summary log
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_sync_unresolvable_409_conflict_logs_summary_warning(monkeypatch, caplog):
    _install_fake_apple_client(monkeypatch, apple_users=[], simulate_409=True)

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        result = await apple.sync_users("token", [_authentik_scim()])

    assert result.conflicts == 1
    assert result.created == 0
    assert "account(s) pending user acceptance" in caplog.text


# ---------------------------------------------------------------------------
# sync_users: a network error during per-user processing is caught and counted
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_sync_network_error_during_user_processing_counts_error(monkeypatch, caplog):
    _install_fake_apple_client(monkeypatch, apple_users=[], raise_network_error=True)

    with caplog.at_level(logging.ERROR, logger="app.scim.apple"):
        result = await apple.sync_users("token", [_authentik_scim()])

    assert result.errors == 1
    assert result.created == 0
    assert "Apple SCIM: network error for externalId=" in caplog.text
