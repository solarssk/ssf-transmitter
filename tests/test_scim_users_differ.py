"""Tests for apple.py SCIM comparison logic (_users_differ, _primary_email)."""

from __future__ import annotations

import dataclasses
import json
import logging
from urllib.parse import parse_qs, urlsplit

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


@pytest.fixture(autouse=True)
def username_recovery_disabled(monkeypatch):
    monkeypatch.setattr(apple, "settings", dataclasses.replace(real_settings, apple_scim_allow_username_recovery=False))


@pytest.fixture
def allow_username_recovery(monkeypatch):
    monkeypatch.setattr(apple, "settings", dataclasses.replace(real_settings, apple_scim_allow_username_recovery=True))


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
    def test_rejects_missing_external_id_by_default(self):
        assert _can_recover_by_username({"userName": "a@example.com"}, "1") is False

    def test_allows_missing_external_id_with_explicit_opt_in(self, allow_username_recovery):
        assert _can_recover_by_username({"userName": "a@example.com"}, "1") is True

    def test_rejects_blank_authentik_external_id_even_with_opt_in(self, allow_username_recovery):
        assert _can_recover_by_username({"userName": "a@example.com"}, "") is False

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
        diffs = {
            "externalId": True,
            "userName": True,
            "givenName": True,
            "familyName": True,
            "email": True,
            "active": True,
        }
        method, body, fields = _build_update_request(user, "patch_all", "apple-1", diffs=diffs)
        assert method == "PATCH"
        assert fields == ["externalId", "userName", "name.givenName", "name.familyName", "emails", "active"]
        assert body["Operations"] == [
            {"op": "Replace", "path": "externalId", "value": "42"},
            {"op": "Replace", "path": "userName", "value": user["userName"]},
            {"op": "Replace", "path": "name.givenName", "value": user["name"]["givenName"]},
            {"op": "Replace", "path": "name.familyName", "value": user["name"]["familyName"]},
            {"op": "Replace", "path": "emails", "value": user["emails"]},
            {"op": "Replace", "path": "active", "value": user["active"]},
        ]

    @pytest.mark.parametrize(
        ("diffs", "expected"),
        [
            ({"externalId": True}, ["externalId"]),
            ({"userName": True}, ["userName"]),
            ({"givenName": True, "familyName": False}, ["name.givenName"]),
            ({"givenName": False, "familyName": True}, ["name.familyName"]),
            ({"givenName": True, "familyName": True}, ["name.givenName", "name.familyName"]),
            ({"email": True}, ["emails"]),
            ({"active": True}, ["active"]),
            ({"email": True, "active": True, "givenName": False}, ["emails", "active"]),
        ],
    )
    def test_patch_all_only_includes_changed_attributes(self, diffs, expected):
        user = _authentik_user()
        user["externalId"] = "42"
        method, body, fields = _build_update_request(user, "patch_all", "apple-1", diffs=diffs)
        assert method == "PATCH"
        assert fields == expected
        assert [op["path"] for op in body["Operations"]] == expected

    def test_patch_preserves_empty_changed_name_value(self):
        user = _authentik_user(family="")
        method, body, fields = _build_update_request(user, "patch_all", "apple-1", diffs={"familyName": True})
        assert method == "PATCH"
        assert fields == ["name.familyName"]
        assert body["Operations"] == [{"op": "Replace", "path": "name.familyName", "value": ""}]

    def test_external_id_only_mode_builds_single_operation(self):
        user = _authentik_user()
        user["externalId"] = "42"
        method, body, fields = _build_update_request(
            user, "external_id_only", "apple-1", diffs={"externalId": True, "email": True}
        )
        assert method == "PATCH"
        assert fields == ["externalId"]
        assert body["Operations"] == [{"op": "Replace", "path": "externalId", "value": "42"}]

    def test_patch_without_in_scope_differences_is_rejected(self):
        user = _authentik_user()
        user["externalId"] = "42"
        with pytest.raises(ValueError, match="without changed attributes"):
            _build_update_request(user, "external_id_only", "apple-1", diffs={"externalId": False, "email": True})

    def test_replace_all_mode_builds_put(self):
        """Apple rejects a PUT body containing `externalId` (immutable) or
        missing the resource `id` — regression test for a real bug where
        this mode sent the raw Authentik-mapped dict (externalId present,
        no id) and every replace_all-mode update permanently failed."""
        user = _authentik_user()
        user["externalId"] = "42"
        method, body, fields = _build_update_request(user, "replace_all", "apple-1", diffs={"email": True})
        assert method == "PUT"
        assert "externalId" not in body
        assert body["id"] == "apple-1"
        assert body["userName"] == user["userName"]
        assert body["name"] == user["name"]
        assert body["emails"] == user["emails"]
        assert fields == ["userName", "name", "emails", "active"]


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
    def test_empty_page_with_positive_total_fails_closed(self):
        data = {"totalResults": 5, "startIndex": 1, "itemsPerPage": 0, "Resources": []}
        with pytest.raises(apple.AppleUserListError):
            _next_users_page_url(data)

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
    def __init__(self, status_code: int, payload: dict | list | None = None, *, bad_json: bool = False):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
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
        reject_name_patch: bool = False,
        list_failure: str | None = None,
        filter_failure: str | None = None,
        list_pages: list[_FakeResponse | httpx.HTTPError] | None = None,
        ignore_external_id_patch: bool = False,
        verification_failure: str | None = None,
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
        self.reject_name_patch = reject_name_patch
        self.list_failure = list_failure
        self.filter_failure = filter_failure
        self.list_pages = list(list_pages) if list_pages is not None else None
        self.ignore_external_id_patch = ignore_external_id_patch
        self.verification_failure = verification_failure
        if holder is not None:
            holder["client"] = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers):
        self.requests.append(("GET", url, None))
        if "/Users/" in url and "filter=" not in url:
            if self.verification_failure == "network":
                raise httpx.ConnectError("connection refused")
            if self.verification_failure == "non_200":
                return _FakeResponse(500, {})
            if self.verification_failure == "bad_json":
                return _FakeResponse(200, bad_json=True)
            for user in self.apple_users:
                if user.get("id") == url.rsplit("/", 1)[-1]:
                    if self.verification_failure == "mismatch":
                        return _FakeResponse(200, {**user, "userName": "other@example.com"})
                    if self.verification_failure == "malformed_name":
                        return _FakeResponse(200, {**user, "name": None})
                    return _FakeResponse(200, user)
            return _FakeResponse(404, {})
        if "filter=" not in url and self.list_pages is not None:
            page = self.list_pages.pop(0)
            if isinstance(page, httpx.HTTPError):
                raise page
            return page
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
        if self.reject_name_patch and any(op.get("path") == "name" for op in ops):
            return _FakeResponse(400, {"scimType": "invalidValue", "detail": "Invalid fieldName = name"})
        is_external_id_repair = len(ops) == 1 and ops[0].get("path") == "externalId"
        if is_external_id_repair and self.fail_external_id_patch:
            return _FakeResponse(self.external_id_patch_status, {"scimType": "invalidValue"})
        if is_external_id_repair and self.ignore_external_id_patch:
            return _FakeResponse(200, {})
        if not is_external_id_repair and self.fail_patch:
            return _FakeResponse(self.fail_patch_status, {"scimType": "invalidValue"})
        apple_id = url.rsplit("/", 1)[-1]
        for user in self.apple_users:
            if user.get("id") == apple_id:
                for op in ops:
                    path = op.get("path")
                    if path and path.startswith("name."):
                        user.setdefault("name", {})[path.removeprefix("name.")] = op.get("value")
                    elif path:
                        user[path] = op.get("value")
                return _FakeResponse(200, user)
        return _FakeResponse(404, {})


class _FilterResponseClient(_FakeAppleClient):
    """Fake Apple client with a specific filtered lookup response."""

    def __init__(self, payload, **kwargs):
        super().__init__(30.0, **kwargs)
        self.payload = payload

    async def get(self, url, headers):
        if "filter=" in url:
            self.requests.append(("GET", url, None))
            return _FakeResponse(200, self.payload)
        return await super().get(url, headers)


class _ObservedAppleClient(_FakeAppleClient):
    """Fake the Apple listing and exact-filter formats observed in production."""

    def __init__(self, *, apple_users=None, sample_users=None, filter_overrides=None, appearing_user=None, **kwargs):
        super().__init__(30.0, apple_users=apple_users, **kwargs)
        self.sample_users = sample_users
        self.filter_overrides = filter_overrides or {}
        self.appearing_user = appearing_user

    async def get(self, url, headers):
        if "/Users/" in url and "filter=" not in url:
            return await super().get(url, headers)
        if "filter=" in url:
            self.requests.append(("GET", url, None))
            query = parse_qs(urlsplit(url).query)
            attribute, literal = query["filter"][0].split(" eq ", 1)
            value = json.loads(literal)
            assert query["count"] == ["2"]
            override = self.filter_overrides.get((attribute, value))
            if isinstance(override, httpx.HTTPError):
                raise override
            if override is not None:
                return override
            users = [
                user
                for user in self.apple_users
                if (
                    apple._normalize_identifier(user.get(attribute)) == apple._normalize_identifier(value)
                    if attribute == "userName"
                    else str(user.get(attribute) or "").strip() == value
                )
            ]
            payload = {"totalResults": len(users), "startIndex": 0, "itemsPerPage": len(users)}
            if users:
                payload["Resources"] = users
            return _FakeResponse(200, payload)

        self.requests.append(("GET", url, None))
        users = self.apple_users[:200] if self.sample_users is None else self.sample_users
        return _FakeResponse(
            200, {"Resources": users, "totalResults": len(users), "startIndex": len(users) + 1, "itemsPerPage": 200}
        )

    async def post(self, url, json, headers):
        response = await super().post(url, json, headers)
        if response.status_code == 409 and self.appearing_user is not None:
            self.apple_users.append(self.appearing_user)
        return response


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
    reject_name_patch: bool = False,
    list_pages: list[_FakeResponse | httpx.HTTPError] | None = None,
    ignore_external_id_patch: bool = False,
    verification_failure: str | None = None,
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
                reject_name_patch=reject_name_patch,
                list_pages=list_pages,
                ignore_external_id_patch=ignore_external_id_patch,
                verification_failure=verification_failure,
            )

    monkeypatch.setattr(apple.httpx, "AsyncClient", _BoundFakeAppleClient)
    return holder


def _apple_existing(external_id="1", username="user@example.com", email="user@example.com", primary=None):
    user = _apple_user(username=username, email=email, email_primary=primary)
    user["id"] = "apple-1"
    if external_id is not None:
        user["externalId"] = external_id
    return user


def _apple_user_list(count: int) -> list[dict]:
    users = []
    for index in range(1, count + 1):
        username = f"user{index}@example.com"
        user = _apple_existing(external_id=str(index), username=username, email=username)
        user["id"] = f"apple-{index}"
        users.append(user)
    return users


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
    """A changed email is patched once and remains unchanged on the next sync."""
    from app.scim import apple

    holder = _install_fake_apple_client(
        monkeypatch, apple_users=[_apple_existing(email="old@example.com")], reject_name_patch=True
    )

    result = await apple.sync_users("token", [_authentik_scim(email="new@example.com")])
    first_requests = list(holder["client"].requests)
    second = await apple.sync_users("token", [_authentik_scim(email="new@example.com")])
    all_requests = first_requests + holder["client"].requests

    assert result.updated == 1
    assert second.unchanged == 1
    patches = [body for method, _, body in all_requests if method == "PATCH"]
    assert len(patches) == 1
    assert [operation["path"] for operation in patches[0]["Operations"]] == ["emails"]


@pytest.mark.parametrize(
    ("name_changes", "expected_paths"),
    [
        ({"givenName": "Jonathan"}, ["name.givenName"]),
        ({"familyName": "Smith"}, ["name.familyName"]),
        ({"givenName": "Jonathan", "familyName": "Smith"}, ["name.givenName", "name.familyName"]),
    ],
)
@pytest.mark.anyio
async def test_sync_changed_name_updates_only_changed_subattributes(monkeypatch, name_changes, expected_paths):
    """Name patches leave unrelated Apple name subattributes untouched."""
    existing = _apple_existing()
    existing["name"]["middleName"] = "Example"
    existing["name"]["formatted"] = "John Example Doe"
    holder = _install_fake_apple_client(monkeypatch, apple_users=[existing], reject_name_patch=True)
    user = _authentik_scim()
    user["name"].update(name_changes)

    result = await apple.sync_users("token", [user])
    first_requests = list(holder["client"].requests)
    second = await apple.sync_users("token", [user])
    all_requests = first_requests + holder["client"].requests

    assert result.updated == 1
    assert result.errors == 0
    assert second.unchanged == 1
    assert existing["name"]["middleName"] == "Example"
    assert existing["name"]["formatted"] == "John Example Doe"
    patches = [body for method, _, body in all_requests if method == "PATCH"]
    assert len(patches) == 1
    assert patches[0]["Operations"] == [
        {"op": "Replace", "path": path, "value": user["name"][path.removeprefix("name.")]} for path in expected_paths
    ]


@pytest.mark.anyio
async def test_sync_reports_rejected_name_update_without_claiming_success(monkeypatch):
    """Rejected name updates count as errors rather than successful writes."""
    holder = _install_fake_apple_client(
        monkeypatch, apple_users=[_apple_existing()], reject_name_patch=True, fail_patch=True, fail_patch_status=400
    )
    user = _authentik_scim()
    user["name"]["givenName"] = "Jonathan"

    result = await apple.sync_users("token", [user])

    assert result.errors == 1
    assert result.update_400_invalid_request == 1
    assert result.updated == 0
    patches = [body for method, _, body in holder["client"].requests if method == "PATCH"]
    assert [operation["path"] for operation in patches[0]["Operations"]] == ["name.givenName"]


@pytest.mark.anyio
async def test_sync_skips_username_match_with_different_external_id(monkeypatch):
    """A username owned by a different external ID cannot be adopted."""
    from app.scim import apple

    holder = _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(external_id="99")])

    result = await apple.sync_users("token", [_authentik_scim(external_id="1")])

    assert result.updated == 0
    assert result.created == 0
    assert result.conflicts == 1
    methods = [r[0] for r in holder["client"].requests]
    assert methods == ["GET"]


@pytest.mark.anyio
async def test_sync_unlinked_username_match_is_a_conflict_by_default(monkeypatch):
    """Unlinked username matches are not modified without an explicit opt-in."""
    existing = _apple_existing(external_id=None, email="stale@example.com")
    holder = _install_fake_apple_client(monkeypatch, apple_users=[existing])

    result = await apple.sync_users("token", [_authentik_scim(email="fresh@example.com")])

    assert result.conflicts == 1
    assert result.created == result.updated == result.errors == 0
    assert existing.get("externalId") is None
    assert [method for method, _, _ in holder["client"].requests] == ["GET"]


@pytest.mark.parametrize("other_external_id", ["2", None])
@pytest.mark.parametrize("allow_recovery", [False, True])
@pytest.mark.anyio
async def test_sync_rejects_username_already_owned_by_another_apple_user(
    monkeypatch, other_external_id, allow_recovery
):
    """A linked user's new username cannot take over a different Apple account."""
    monkeypatch.setattr(
        apple, "settings", dataclasses.replace(real_settings, apple_scim_allow_username_recovery=allow_recovery)
    )
    linked = _apple_existing(external_id="1", username="old@example.com", email="old@example.com")
    other = _apple_existing(external_id=other_external_id, username="user@example.com")
    other["id"] = "apple-2"
    holder = _install_fake_apple_client(monkeypatch, apple_users=[linked, other])

    result = await apple.sync_users("token", [_authentik_scim(external_id="1")])

    assert result.conflicts == 1
    assert result.created == result.updated == result.errors == 0
    assert [method for method, _, _ in holder["client"].requests] == ["GET"]


@pytest.mark.anyio
async def test_sync_recovered_by_username_missing_external_id_patches_once_then_unchanged(
    monkeypatch, allow_username_recovery
):
    """An opted-in identity repair is verified and not repeated on the next sync."""
    from app.scim import apple

    holder = _install_fake_apple_client(monkeypatch, apple_users=[_apple_existing(external_id=None)])

    first = await apple.sync_users("token", [_authentik_scim(external_id="1")])
    first_requests = list(holder["client"].requests)
    second = await apple.sync_users("token", [_authentik_scim(external_id="1")])
    methods = [r[0] for r in first_requests + holder["client"].requests]
    assert first.updated == 1
    assert second.unchanged == 1
    assert methods.count("PATCH") == 1
    assert [method for method, _, _ in first_requests] == ["GET", "PATCH", "GET"]


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

    scoped_settings = dataclasses.replace(
        real_settings, apple_scim_update_mode="replace_all", apple_scim_allow_username_recovery=True
    )
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
async def test_sync_failed_external_id_repair_is_not_also_counted_unchanged(monkeypatch, allow_username_recovery):
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
async def test_handle_409_failed_external_id_repair_is_not_also_counted_unchanged(allow_username_recovery):
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


@pytest.mark.parametrize("mode", ["patch_all", "replace_all"])
@pytest.mark.anyio
async def test_failed_identity_link_does_not_update_other_fields(monkeypatch, mode):
    """A failed identity repair blocks subsequent updates in both write modes."""
    scoped_settings = dataclasses.replace(
        real_settings, apple_scim_update_mode=mode, apple_scim_allow_username_recovery=True
    )
    monkeypatch.setattr(apple, "settings", scoped_settings)
    existing = _apple_existing(external_id=None, email="old@example.com")
    holder = _install_fake_apple_client(monkeypatch, apple_users=[existing], fail_external_id_patch=True)

    result = await apple.sync_users("token", [_authentik_scim(email="new@example.com")])

    assert result.errors == 1
    assert result.updated == 0
    patches = [body for method, _, body in holder["client"].requests if method == "PATCH"]
    assert len(patches) == 1
    assert [operation["path"] for operation in patches[0]["Operations"]] == ["externalId"]
    assert all(method != "PUT" for method, _, _ in holder["client"].requests)
    assert existing["emails"][0]["value"] == "old@example.com"


@pytest.mark.parametrize("failure", ["ignored", "network", "non_200", "bad_json", "mismatch", "malformed_name"])
@pytest.mark.anyio
async def test_unverified_identity_link_does_not_update_other_fields(monkeypatch, allow_username_recovery, failure):
    """Unverified identity repairs never authorize unrelated account updates."""
    existing = _apple_existing(external_id=None, email="old@example.com")
    holder = _install_fake_apple_client(
        monkeypatch,
        apple_users=[existing],
        ignore_external_id_patch=failure == "ignored",
        verification_failure=None if failure == "ignored" else failure,
    )

    result = await apple.sync_users("token", [_authentik_scim(email="new@example.com")])

    assert result.errors == 1
    assert result.updated == 0
    patches = [body for method, _, body in holder["client"].requests if method == "PATCH"]
    assert len(patches) == 1
    assert [operation["path"] for operation in patches[0]["Operations"]] == ["externalId"]
    assert existing["emails"][0]["value"] == "old@example.com"


@pytest.mark.anyio
async def test_identity_link_uses_verified_user_for_subsequent_diffs(allow_username_recovery):
    """Post-repair diffs use the verified Apple record, not its stale listing."""
    listed_user = _apple_existing(external_id=None, email="old@example.com")
    current_user = _apple_existing(external_id=None, email="new@example.com")
    fake_client = _FakeAppleClient(30.0, apple_users=[current_user])
    result = apple.SyncResult()

    await apple._reconcile_diffs(
        fake_client,
        {},
        listed_user,
        _authentik_scim(email="new@example.com"),
        result,
        recovered_by_username=True,
    )

    assert result.updated == 1
    assert result.errors == 0
    assert [method for method, _, _ in fake_client.requests] == ["PATCH", "GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("has_username", [True, False])
async def test_username_recovery_rejects_missing_authentik_external_id(has_username):
    """A username match cannot be adopted without a stable Authentik identity."""
    fake_client = _FakeAppleClient(30.0)
    result = apple.SyncResult()
    user = _authentik_scim(external_id="")
    if not has_username:
        user.pop("userName")

    await apple._reconcile_diffs(
        fake_client,
        {},
        _apple_existing(external_id=None),
        user,
        result,
        recovered_by_username=True,
    )

    assert result.conflicts == 1
    assert result.conflict_usernames == ([user["userName"]] if has_username else [])
    assert result.updated == result.errors == 0
    assert fake_client.requests == []


# ---------------------------------------------------------------------------
# _get_existing_users: upstream listing failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_get_existing_users_non_200_response_fails(caplog):
    from app.scim import apple

    fake_client = _FakeAppleClient(30.0, list_failure="non_200")

    with caplog.at_level(logging.ERROR, logger="app.scim.apple"), pytest.raises(apple.AppleUserListError):
        await apple._get_existing_users(fake_client, {})

    assert "Apple SCIM list users failed" in caplog.text


@pytest.mark.anyio
async def test_get_existing_users_non_json_response_fails(caplog):
    from app.scim import apple

    fake_client = _FakeAppleClient(30.0, list_failure="bad_json")

    with caplog.at_level(logging.ERROR, logger="app.scim.apple"), pytest.raises(apple.AppleUserListError):
        await apple._get_existing_users(fake_client, {})

    assert "non-JSON response" in caplog.text


@pytest.mark.anyio
@pytest.mark.parametrize("after_first_page", [False, True])
@pytest.mark.parametrize(
    "failure",
    [
        "429",
        "500",
        "network",
        "bad_json",
        "not_object",
        "missing_total",
        "empty_page",
        "bad_count",
        "bad_start",
        "missing_id",
        "invalid_id",
        "missing_username",
        "bad_resource",
        "over_total",
    ],
)
async def test_incomplete_apple_listing_aborts_without_writes(monkeypatch, after_first_page, failure):
    """Invalid or unavailable pages abort the entire sync before any writes."""
    first_user = _apple_existing()
    start = 2 if after_first_page else 1
    page = {"Resources": [_apple_existing(external_id="2")], "totalResults": 2, "startIndex": start, "itemsPerPage": 1}
    if failure == "429":
        failed_page = _FakeResponse(429)
    elif failure == "500":
        failed_page = _FakeResponse(500)
    elif failure == "network":
        failed_page = httpx.ConnectError("connection refused")
    elif failure == "bad_json":
        failed_page = _FakeResponse(200, bad_json=True)
    elif failure == "not_object":
        failed_page = _FakeResponse(200, [])
    else:
        if failure == "missing_total":
            del page["totalResults"]
        elif failure == "empty_page":
            page["Resources"] = []
            page["itemsPerPage"] = 0
        elif failure == "bad_count":
            page["itemsPerPage"] = 2
        elif failure == "bad_start":
            page["startIndex"] = start + 1
        elif failure == "missing_id":
            del page["Resources"][0]["id"]
        elif failure == "invalid_id":
            page["Resources"][0]["id"] = "../other"
        elif failure == "missing_username":
            del page["Resources"][0]["userName"]
        elif failure == "bad_resource":
            page["Resources"] = ["not a user"]
        elif failure == "over_total":
            page["Resources"] = [_apple_existing(), _apple_existing(external_id="2")]
            if not after_first_page:
                page["Resources"].append(_apple_existing(external_id="3"))
            page["itemsPerPage"] = len(page["Resources"])
        failed_page = _FakeResponse(200, page)

    pages = []
    if after_first_page:
        pages.append(
            _FakeResponse(200, {"Resources": [first_user], "totalResults": 2, "startIndex": 1, "itemsPerPage": 1})
        )
    pages.append(failed_page)
    holder = _install_fake_apple_client(monkeypatch, list_pages=pages)

    users = [_authentik_scim(), _authentik_scim(external_id="2")]
    with pytest.raises(apple.AppleUserListError):
        await apple.sync_users("token", users)

    assert len(holder["client"].requests) == (2 if after_first_page else 1)
    assert all(method == "GET" for method, _, _ in holder["client"].requests)


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["duplicate_id", "duplicate_external_id", "duplicate_username", "total_changed"])
async def test_inconsistent_apple_pages_abort_without_writes(monkeypatch, failure):
    """Duplicate identities or changing totals invalidate the whole listing."""
    first = _apple_existing()
    second = _apple_existing(external_id="2", username="second@example.com")
    second["id"] = "apple-2"
    if failure == "duplicate_id":
        second["id"] = first["id"]
    elif failure == "duplicate_external_id":
        second["externalId"] = first["externalId"]
    elif failure == "duplicate_username":
        second["userName"] = first["userName"].upper()
    total = 3 if failure == "total_changed" else 2
    holder = _install_fake_apple_client(
        monkeypatch,
        list_pages=[
            _FakeResponse(200, {"Resources": [first], "totalResults": 2, "startIndex": 1, "itemsPerPage": 1}),
            _FakeResponse(200, {"Resources": [second], "totalResults": total, "startIndex": 2, "itemsPerPage": 1}),
        ],
    )

    users = [_authentik_scim()]
    with pytest.raises(apple.AppleUserListError):
        await apple.sync_users("token", users)

    assert [method for method, _, _ in holder["client"].requests] == ["GET", "GET"]


@pytest.mark.anyio
async def test_complete_apple_listing_uses_all_pages_before_writing(monkeypatch):
    """Every Apple page is indexed before reconciling any Authentik user."""
    first = _apple_existing()
    second = _apple_existing(external_id="2", username="second@example.com", email="second@example.com")
    second["id"] = "apple-2"
    holder = _install_fake_apple_client(
        monkeypatch,
        list_pages=[
            _FakeResponse(200, {"Resources": [first], "totalResults": 2, "startIndex": 1, "itemsPerPage": 1}),
            _FakeResponse(200, {"Resources": [second], "totalResults": 2, "startIndex": 2, "itemsPerPage": 1}),
        ],
    )

    result = await apple.sync_users(
        "token",
        [
            _authentik_scim(),
            _authentik_scim(external_id="2", username="second@example.com", email="second@example.com"),
        ],
    )

    assert result.unchanged == 2
    assert [method for method, _, _ in holder["client"].requests] == ["GET", "GET"]
    assert holder["client"].requests[1][1].endswith("/Users?count=200&startIndex=2")


@pytest.mark.anyio
async def test_complete_listing_accepts_missing_optional_pagination_metadata():
    first = _apple_existing()
    second = _apple_existing(external_id="2", username="second@example.com")
    second["id"] = "apple-2"
    fake_client = _FakeAppleClient(
        30.0,
        list_pages=[
            _FakeResponse(200, {"Resources": [first], "totalResults": 2}),
            _FakeResponse(200, {"Resources": [second], "totalResults": 2}),
        ],
    )

    by_external_id, by_username = await apple._get_existing_users(fake_client, {})

    assert set(by_external_id) == {"1", "2"}
    assert set(by_username) == {"user@example.com", "second@example.com"}
    assert fake_client.requests[1][1].endswith("/Users?count=200&startIndex=2")


@pytest.mark.anyio
async def test_sync_accepts_observed_apple_single_page_metadata(monkeypatch):
    """A count-relative Apple listing triggers verified individual lookups."""
    users = _apple_user_list(7)
    client = _ObservedAppleClient(apple_users=users)
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users(
        "token",
        [_authentik_scim(external_id="7", username="user7@example.com", email="user7@example.com")],
    )

    assert result.unchanged == 1
    assert result.created == result.updated == result.errors == result.conflicts == 0
    assert [method for method, _, _ in client.requests] == ["GET"] * 4
    assert client.requests[0][1].endswith("/Users?count=200")
    assert "externalId%20eq%20" in client.requests[1][1]
    assert "userName%20eq%20" in client.requests[2][1]
    assert client.requests[3][1].endswith("/Users/apple-7")


@pytest.mark.anyio
async def test_apple_empty_single_page_metadata_can_create_user(monkeypatch):
    """Creation requires empty responses to both individual filters."""
    client = _ObservedAppleClient()
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.created == 1
    assert [method for method, _, _ in client.requests] == ["GET", "GET", "GET", "POST", "GET", "GET", "GET"]


@pytest.mark.anyio
async def test_apple_single_page_finds_user_beyond_200(monkeypatch):
    """A full Apple sample does not hide a matching user outside the sample."""
    users = _apple_user_list(201)
    client = _ObservedAppleClient(apple_users=users)
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users(
        "token",
        [_authentik_scim(external_id="201", username="user201@example.com", email="user201@example.com")],
    )

    assert result.unchanged == 1
    assert [method for method, _, _ in client.requests] == ["GET"] * 4
    assert client.requests[-1][1].endswith("/Users/apple-201")


@pytest.mark.anyio
async def test_standard_pagination_accepts_a_full_first_page(monkeypatch):
    """The Apple compatibility limit does not replace standard multi-page validation."""
    users = _apple_user_list(201)
    holder = _install_fake_apple_client(
        monkeypatch,
        list_pages=[
            _FakeResponse(200, {"Resources": users[:200], "totalResults": 201, "startIndex": 1, "itemsPerPage": 200}),
            _FakeResponse(200, {"Resources": users[200:], "totalResults": 201, "startIndex": 201, "itemsPerPage": 1}),
        ],
    )

    result = await apple.sync_users(
        "token",
        [_authentik_scim(external_id="201", username="user201@example.com", email="user201@example.com")],
    )

    assert result.unchanged == 1
    assert [method for method, _, _ in holder["client"].requests] == ["GET", "GET"]
    assert holder["client"].requests[1][1].endswith("/Users?count=200&startIndex=201")


@pytest.mark.anyio
async def test_apple_single_page_uses_confirmed_user_attributes(monkeypatch):
    """The exact GET is used when non-identity fields changed since the sample."""
    first = _apple_existing(email="old@example.com")
    confirmed = _apple_existing(email="user@example.com")
    client = _ObservedAppleClient(apple_users=[confirmed], sample_users=[first])
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.unchanged == 1
    assert [method for method, _, _ in client.requests] == ["GET"] * 4


@pytest.mark.anyio
async def test_hidden_lower_listing_limit_does_not_create_duplicate(monkeypatch):
    """A user missing from the first listing is found via both filters."""
    first, target = _apple_user_list(2)
    target["emails"][0]["value"] = "stale@example.com"
    client = _ObservedAppleClient(apple_users=[first, target], sample_users=[first])
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users(
        "token",
        [_authentik_scim(external_id="2", username="user2@example.com", email="user2@example.com")],
    )

    assert result.updated == 1
    assert result.created == result.errors == result.conflicts == 0
    assert [method for method, _, _ in client.requests] == ["GET", "GET", "GET", "GET", "PATCH"]
    assert client.requests[-1][1].endswith("/Users/apple-2")


@pytest.mark.anyio
async def test_filtered_external_id_preserves_link_after_username_change(monkeypatch):
    existing = _apple_existing(username="old@example.com", email="old@example.com")
    client = _ObservedAppleClient(apple_users=[existing])
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users("token", [_authentik_scim(username="new@example.com", email="new@example.com")])

    assert result.updated == 1
    assert result.created == result.conflicts == result.errors == 0
    assert existing["userName"] == "new@example.com"
    assert existing["externalId"] == "1"
    assert all(method != "POST" for method, _, _ in client.requests)


@pytest.mark.anyio
async def test_filtered_lookup_detects_username_owned_by_different_user(monkeypatch):
    first = _apple_existing(external_id="1", username="old@example.com")
    second = _apple_existing(external_id="2", username="new@example.com")
    second["id"] = "apple-2"
    client = _ObservedAppleClient(apple_users=[first, second])
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users("token", [_authentik_scim(external_id="1", username="new@example.com")])

    assert result.conflicts == 1
    assert result.created == result.updated == result.errors == 0
    assert all(method == "GET" for method, _, _ in client.requests)


@pytest.mark.anyio
async def test_filtered_lookup_does_not_automatically_adopt_unlinked_account(monkeypatch):
    existing = _apple_existing(external_id=None)
    client = _ObservedAppleClient(apple_users=[existing])
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.conflicts == 1
    assert result.created == result.updated == result.errors == 0
    assert all(method == "GET" for method, _, _ in client.requests)


@pytest.mark.anyio
async def test_filtered_lookup_opt_in_verifies_unlinked_account(monkeypatch, allow_username_recovery):
    existing = _apple_existing(external_id=None)
    client = _ObservedAppleClient(apple_users=[existing])
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.updated == 1
    assert result.conflicts == result.created == result.errors == 0
    assert existing["externalId"] == "1"
    assert [method for method, _, _ in client.requests] == ["GET", "GET", "GET", "GET", "PATCH", "GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["network", "non_200", "bad_json", "mismatch", "malformed_name"])
async def test_filtered_exact_user_verification_failure_aborts_before_writes(monkeypatch, failure):
    existing = _apple_existing(email="stale@example.com")
    client = _ObservedAppleClient(apple_users=[existing], verification_failure=failure)
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    with pytest.raises(apple.AppleUserListError):
        await apple.sync_users("token", [_authentik_scim()])

    assert [method for method, _, _ in client.requests] == ["GET"] * 4


@pytest.mark.anyio
async def test_filtered_lookups_disagreeing_about_same_id_abort(monkeypatch):
    existing = _apple_existing()
    conflicting = {**existing, "externalId": "other"}
    override = _FakeResponse(200, {"Resources": [conflicting], "totalResults": 1, "startIndex": 0, "itemsPerPage": 1})
    client = _ObservedAppleClient(
        apple_users=[existing], sample_users=[], filter_overrides={("userName", "user@example.com"): override}
    )
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    with pytest.raises(apple.AppleUserListError, match="disagree"):
        await apple.sync_users("token", [_authentik_scim()])

    assert [method for method, _, _ in client.requests] == ["GET"] * 3


@pytest.mark.anyio
async def test_filtered_negative_conflicting_with_verified_user_aborts(monkeypatch):
    existing = _apple_existing()
    empty = _FakeResponse(200, {"totalResults": 0, "startIndex": 0, "itemsPerPage": 0})
    client = _ObservedAppleClient(
        apple_users=[existing], sample_users=[], filter_overrides={("userName", "user@example.com"): empty}
    )
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    with pytest.raises(apple.AppleUserListError, match="inconsistent identities"):
        await apple.sync_users("token", [_authentik_scim()])

    assert [method for method, _, _ in client.requests] == ["GET"] * 4


@pytest.mark.anyio
@pytest.mark.parametrize("invalid", ["missing_external_id", "missing_username", "non_string_username"])
async def test_filtered_preflight_rejects_invalid_source_identity(monkeypatch, invalid):
    user = _authentik_scim()
    if invalid == "missing_external_id":
        user["externalId"] = ""
    elif invalid == "missing_username":
        user["userName"] = " "
    else:
        user["userName"] = None
    client = _ObservedAppleClient()
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    with pytest.raises(apple.AppleUserListError, match="invalid identity"):
        await apple.sync_users("token", [user])

    assert [method for method, _, _ in client.requests] == ["GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("duplicate", ["external_id", "username"])
async def test_filtered_preflight_rejects_duplicate_source_identities(monkeypatch, duplicate):
    first = _authentik_scim()
    second = _authentik_scim(external_id="2", username="second@example.com")
    if duplicate == "external_id":
        second["externalId"] = "1"
    else:
        second["userName"] = "USER@example.com"
    client = _ObservedAppleClient()
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    with pytest.raises(apple.AppleUserListError, match="duplicate identities"):
        await apple.sync_users("token", [first, second])

    assert [method for method, _, _ in client.requests] == ["GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("bad_response", ["missing_id", "wrong_id", "filter_failure", "bad_json"])
async def test_filtered_create_never_reports_unverified_success(monkeypatch, caplog, bad_response):
    class Client(_ObservedAppleClient):
        async def post(self, url, json, headers):
            response = await super().post(url, json, headers)
            if bad_response == "filter_failure":
                self.filter_overrides[("externalId", "1")] = _FakeResponse(500)
            elif bad_response == "missing_id":
                return _FakeResponse(201, {})
            elif bad_response == "bad_json":
                return _FakeResponse(201, bad_json=True)
            else:
                return _FakeResponse(201, {"id": "wrong-id"})
            return response

    client = Client()
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.errors == 1
    assert result.created == result.updated == result.conflicts == 0
    assert [method for method, _, _ in client.requests].count("POST") == 1
    assert "create may have succeeded" in caplog.text
    assert "user@example.com" not in caplog.text


@pytest.mark.anyio
@pytest.mark.parametrize("attribute", ["externalId", "userName"])
async def test_individual_filter_escapes_scim_string_literal(attribute):
    value = 'a"\\name@example.com'
    client = _ObservedAppleClient()

    assert await apple._lookup_filtered_user(client, {}, attribute, value, None) is None

    query = parse_qs(urlsplit(client.requests[0][1]).query)
    encoded_literal = query["filter"][0].removeprefix(f"{attribute} eq ")
    assert json.loads(encoded_literal) == value
    assert query["count"] == ["2"]


@pytest.mark.parametrize(
    "payload",
    [
        {"totalResults": True, "Resources": []},
        {"totalResults": -1, "Resources": []},
        {"totalResults": 0, "Resources": None},
        {"totalResults": 1},
        {"totalResults": 1, "startIndex": False, "Resources": [_apple_existing()]},
        {"totalResults": 1, "itemsPerPage": True, "Resources": [_apple_existing()]},
        {"totalResults": 1, "Resources": ["invalid"]},
        {"totalResults": 1, "Resources": [{**_apple_existing(), "id": "../other"}]},
        {"totalResults": 1, "Resources": [{**_apple_existing(), "userName": ""}]},
    ],
)
def test_filtered_lookup_rejects_invalid_identity_or_metadata(payload):
    with pytest.raises(apple.AppleUserListError):
        apple._validate_filtered_user(payload, "externalId", "1")


def test_filtered_lookup_accepts_observed_empty_apple_response():
    payload = {"totalResults": 0, "startIndex": 0, "itemsPerPage": 0}
    assert apple._validate_filtered_user(payload, "externalId", "missing") is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure",
    [
        "http_error",
        "network",
        "bad_json",
        "wrong_metadata",
        "missing_user",
        "changed_id",
        "changed_username",
        "changed_external_id",
        "duplicate_identity",
        "invalid_name",
        "null_resources",
        "inconsistent_count",
    ],
)
async def test_apple_filtered_lookup_failure_aborts_all_writes(monkeypatch, failure):
    """Failure on a later identity stops earlier accounts from being updated."""
    first = _apple_existing(email="stale@example.com")
    second = _apple_existing(external_id="2", username="second@example.com", email="second@example.com")
    second["id"] = "apple-2"
    found = dict(second)
    users = [found]
    if failure == "missing_user":
        users = []
    elif failure == "changed_id":
        found["id"] = "apple-3"
    elif failure == "changed_username":
        found["userName"] = "other@example.com"
    elif failure == "changed_external_id":
        found["externalId"] = "3"
    elif failure == "duplicate_identity":
        users.append({**found, "id": "apple-3", "userName": "other@example.com"})
    elif failure == "invalid_name":
        found["name"] = None

    payload = {
        "Resources": users,
        "totalResults": len(users),
        "startIndex": 9 if failure == "wrong_metadata" else 0,
        "itemsPerPage": len(users),
    }
    if failure == "null_resources":
        payload.update(Resources=None, totalResults=0, itemsPerPage=0)
    elif failure == "inconsistent_count":
        payload["totalResults"] = 2
    if failure == "network":
        response = httpx.ConnectError("connection refused")
    elif failure == "http_error":
        response = _FakeResponse(500)
    elif failure == "bad_json":
        response = _FakeResponse(200, bad_json=True)
    else:
        response = _FakeResponse(200, payload)
    client = _ObservedAppleClient(
        apple_users=[first, second],
        filter_overrides={("externalId", "2"): response},
    )
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: client)

    with pytest.raises(apple.AppleUserListError):
        await apple.sync_users(
            "token",
            [
                _authentik_scim(email="fresh@example.com"),
                _authentik_scim(external_id="2", username="second@example.com", email="second@example.com"),
            ],
        )

    assert [method for method, _, _ in client.requests] == ["GET"] * 4


@pytest.mark.anyio
async def test_apple_single_page_exceeding_requested_count_aborts_before_writes(monkeypatch):
    users = _apple_user_list(201)
    page = {"Resources": users, "totalResults": 201, "startIndex": 202, "itemsPerPage": 200}
    holder = _install_fake_apple_client(monkeypatch, list_pages=[_FakeResponse(200, page)])

    with pytest.raises(apple.AppleUserListError, match="exceeds the requested count"):
        await apple.sync_users("token", [_authentik_scim()])

    assert [method for method, _, _ in holder["client"].requests] == ["GET"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_start",
        "wrong_total",
        "wrong_count",
        "bool_total",
        "bool_start",
        "bool_count",
        "duplicate_id",
        "invalid_resource",
    ],
)
async def test_invalid_apple_single_page_metadata_aborts_before_writes(monkeypatch, mutation):
    """The compatibility path still rejects malformed or ambiguous listings."""
    first = _apple_existing()
    second = _apple_existing(external_id="2", username="second@example.com")
    second["id"] = "apple-2"
    page = {"Resources": [first, second], "totalResults": 2, "startIndex": 3, "itemsPerPage": 200}
    if mutation == "wrong_start":
        page["startIndex"] = 4
    elif mutation == "wrong_total":
        page["totalResults"] = 3
    elif mutation == "wrong_count":
        page["itemsPerPage"] = 199
    elif mutation == "bool_total":
        page["totalResults"] = True
    elif mutation == "bool_start":
        page["startIndex"] = True
    elif mutation == "bool_count":
        page["itemsPerPage"] = True
    elif mutation == "duplicate_id":
        second["id"] = first["id"]
    else:
        page["Resources"] = [first, "not a user"]
    holder = _install_fake_apple_client(monkeypatch, list_pages=[_FakeResponse(200, page)])

    with pytest.raises(apple.AppleUserListError):
        await apple.sync_users("token", [_authentik_scim()])

    assert [method for method, _, _ in holder["client"].requests] == ["GET"]


@pytest.mark.anyio
async def test_empty_listing_without_resources_can_create_a_user(monkeypatch):
    """A valid empty Apple listing permits creation of a new user."""
    holder = _install_fake_apple_client(monkeypatch, list_pages=[_FakeResponse(200, {"totalResults": 0})])

    result = await apple.sync_users("token", [_authentik_scim()])

    assert result.created == 1
    assert [method for method, _, _ in holder["client"].requests] == ["GET", "POST"]


# ---------------------------------------------------------------------------
# _query_username_filter (via _handle_409): upstream filter-query failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_handle_409_filter_query_network_error_is_an_error(caplog):
    fake_client = _FakeAppleClient(30.0, apple_users=[], filter_failure="network")
    new_user = _authentik_scim()
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.errors == 1
    assert result.conflicts == 0
    assert "409-recovery network error" in caplog.text


@pytest.mark.anyio
async def test_handle_409_filter_query_non_200_is_an_error(caplog):
    fake_client = _FakeAppleClient(30.0, apple_users=[], filter_failure="non_200")
    new_user = _authentik_scim()
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.errors == 1
    assert result.conflicts == 0
    assert "409-recovery filter query failed" in caplog.text


@pytest.mark.anyio
async def test_handle_409_filter_query_non_json_is_an_error(caplog):
    fake_client = _FakeAppleClient(30.0, apple_users=[], filter_failure="bad_json")
    new_user = _authentik_scim()
    result = apple.SyncResult()

    with caplog.at_level(logging.WARNING, logger="app.scim.apple"):
        await apple._handle_409(fake_client, {}, new_user, result)

    assert result.errors == 1
    assert result.conflicts == 0
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
    assert all(method != "PATCH" for method, _, _ in fake_client.requests)


@pytest.mark.anyio
async def test_handle_409_unlinked_username_match_is_a_conflict_by_default():
    """Create-conflict recovery refuses unlinked matches unless opted in."""
    fake_client = _FakeAppleClient(30.0, apple_users=[_apple_existing(external_id=None)])
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(), result)

    assert result.conflicts == 1
    assert result.updated == result.errors == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET"]


@pytest.mark.anyio
async def test_handle_409_opt_in_verifies_link_before_updating(allow_username_recovery):
    """Opted-in recovery verifies the identity link before updating fields."""
    found = _apple_existing(external_id=None, email="old@example.com")
    fake_client = _FakeAppleClient(30.0, apple_users=[found])
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(email="new@example.com"), result)

    assert result.updated == 2
    assert result.errors == result.conflicts == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET", "PATCH", "GET", "PATCH"]
    assert found["externalId"] == "1"
    assert found["emails"][0]["value"] == "new@example.com"


@pytest.mark.anyio
async def test_handle_409_accepts_observed_zero_based_filter_metadata(allow_username_recovery):
    """Apple's zero-based filter result still requires a verified identity repair."""
    found = _apple_existing(external_id=None, email="old@example.com")
    payload = {"Resources": [found], "totalResults": 1, "startIndex": 0, "itemsPerPage": 1}
    fake_client = _FilterResponseClient(payload, apple_users=[found])
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(email="new@example.com"), result)

    assert result.updated == 2
    assert result.errors == result.conflicts == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET", "GET", "PATCH", "GET", "PATCH"]
    assert found["externalId"] == "1"
    assert parse_qs(urlsplit(fake_client.requests[0][1]).query)["count"] == ["2"]


@pytest.mark.anyio
async def test_sync_handles_both_observed_apple_metadata_formats(monkeypatch, allow_username_recovery):
    """An account appearing after the initial listing is verified before 409 recovery."""
    found = _apple_existing(external_id=None, email="old@example.com")
    other = _apple_existing(external_id="2", username="other@example.com", email="other@example.com")
    other["id"] = "apple-2"
    fake_client = _ObservedAppleClient(apple_users=[other], appearing_user=found, simulate_409=True)
    monkeypatch.setattr(apple.httpx, "AsyncClient", lambda timeout: fake_client)

    result = await apple.sync_users("token", [_authentik_scim(email="new@example.com")])

    assert result.updated == 2
    assert result.created == result.errors == result.conflicts == 0
    assert [method for method, _, _ in fake_client.requests] == [
        "GET",
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
        "GET",
        "GET",
        "GET",
        "PATCH",
        "GET",
        "PATCH",
    ]
    assert found["externalId"] == "1"
    assert found["emails"][0]["value"] == "new@example.com"


@pytest.mark.anyio
async def test_zero_based_filter_does_not_enable_username_only_recovery():
    """A verified unlinked account still needs the operator's explicit opt-in."""
    found = _apple_existing(external_id=None)
    payload = {"Resources": [found], "totalResults": 1, "startIndex": 0, "itemsPerPage": 1}
    fake_client = _FilterResponseClient(payload, apple_users=[found])
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(), result)

    assert result.conflicts == 1
    assert result.errors == result.updated == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET", "GET"]


@pytest.mark.anyio
async def test_zero_based_filter_uses_latest_verified_attributes():
    """Reconciliation uses the fresh listing, not stale filtered attributes."""
    filtered = _apple_existing(email="old@example.com")
    listed = _apple_existing(email="user@example.com")
    payload = {"Resources": [filtered], "totalResults": 1, "startIndex": 0, "itemsPerPage": 1}
    fake_client = _FilterResponseClient(payload, apple_users=[listed])
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(), result)

    assert result.unchanged == 1
    assert result.updated == result.errors == result.conflicts == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET", "GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["missing", "different_id", "different_external_id", "duplicate", "list_error"])
async def test_zero_based_filter_must_agree_with_full_listing(allow_username_recovery, failure):
    """A singleton filter response cannot hide a missing, different, or duplicate account."""
    found = _apple_existing(external_id=None, email="old@example.com")
    listed = dict(found)
    users = [] if failure == "missing" else [listed]
    if failure == "different_id":
        listed["id"] = "apple-2"
    elif failure == "different_external_id":
        listed["externalId"] = "2"
    elif failure == "duplicate":
        users.append({**listed, "id": "apple-2"})

    payload = {"Resources": [found], "totalResults": 1, "startIndex": 0, "itemsPerPage": 1}
    fake_client = _FilterResponseClient(
        payload, apple_users=users, list_failure="network" if failure == "list_error" else None
    )
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(email="new@example.com"), result)

    assert result.errors == 1
    assert result.conflicts == result.updated == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET", "GET"]
    assert "externalId" not in found


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("payload", "expected_conflicts"),
    [
        ({"Resources": [], "totalResults": 0, "startIndex": 0, "itemsPerPage": 0}, 1),
        (
            {
                "Resources": [_apple_existing(), _apple_existing()],
                "totalResults": 2,
                "startIndex": 0,
                "itemsPerPage": 2,
            },
            1,
        ),
        ({"Resources": [_apple_existing()], "totalResults": 2, "startIndex": 0, "itemsPerPage": 1}, 1),
        ({"Resources": [_apple_existing(username="other@example.com")], "totalResults": 1, "startIndex": 0}, 0),
        ({"Resources": [_apple_existing()], "totalResults": 1, "startIndex": 0, "itemsPerPage": 2}, 0),
        ({"Resources": [_apple_existing()], "totalResults": 1, "startIndex": False, "itemsPerPage": 1}, 0),
    ],
)
async def test_zero_based_filter_rejects_missing_ambiguous_or_invalid_results(payload, expected_conflicts):
    """Zero-based lookups cannot authorize writes for unsafe or ambiguous results."""
    fake_client = _FilterResponseClient(payload)
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(), result)

    assert result.conflicts == expected_conflicts
    assert result.errors == 1 - expected_conflicts
    assert result.updated == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET"]


@pytest.mark.anyio
async def test_handle_409_failed_link_does_not_update_other_fields(allow_username_recovery):
    """A failed 409-recovery link cannot trigger a follow-up account update."""
    found = _apple_existing(external_id=None, email="old@example.com")
    fake_client = _FakeAppleClient(30.0, apple_users=[found], fail_external_id_patch=True)
    result = apple.SyncResult()

    await apple._handle_409(fake_client, {}, _authentik_scim(email="new@example.com"), result)

    assert result.errors == 1
    assert result.updated == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET", "PATCH"]
    assert found["emails"][0]["value"] == "old@example.com"


@pytest.mark.parametrize(
    ("payload", "expected_conflicts"),
    [
        ({"totalResults": 2, "Resources": [_apple_existing(), _apple_existing()]}, 1),
        ({"totalResults": 2, "Resources": [_apple_existing()]}, 1),
        ({"totalResults": 1, "Resources": [_apple_existing(username="other@example.com")]}, 0),
        ({"totalResults": 1, "Resources": [{**_apple_existing(), "id": "../other"}]}, 0),
        ({"totalResults": 1, "Resources": [_apple_user()]}, 0),
        ({"totalResults": 1, "Resources": ["not a user"]}, 0),
        ({"Resources": [_apple_existing()]}, 0),
        (["not a SCIM object"], 0),
    ],
)
@pytest.mark.anyio
async def test_handle_409_rejects_ambiguous_or_invalid_filter_results(payload, expected_conflicts):
    """Ambiguous or malformed filtered results never trigger Apple writes."""
    fake_client = _FilterResponseClient(payload, apple_users=[_apple_existing(email="stale@example.com")])
    result = apple.SyncResult()
    await apple._handle_409(fake_client, {}, _authentik_scim(), result)

    assert result.conflicts == expected_conflicts
    assert result.errors == 1 - expected_conflicts
    assert result.updated == 0
    assert [method for method, _, _ in fake_client.requests] == ["GET"]


@pytest.mark.anyio
async def test_username_filter_escapes_scim_string_literal():
    username = 'user"\\name@example.com'
    fake_client = _FakeAppleClient(30.0)

    await apple._query_username_filter(fake_client, {}, username, "masked")

    query = parse_qs(urlsplit(fake_client.requests[0][1]).query)
    encoded_literal = query["filter"][0].removeprefix("userName eq ")
    assert json.loads(encoded_literal) == username
    assert query["count"] == ["2"]


def test_user_id_is_encoded_as_one_url_segment():
    assert apple._user_url("id?one#two") == f"{apple.APPLE_SCIM_BASE}/Users/id%3Fone%23two"


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
async def test_external_id_repair_non_400_failure_not_classified(monkeypatch, allow_username_recovery):
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
    assert "account(s) require identity or creation-conflict review" in caplog.text


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
