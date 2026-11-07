"""Apple SCIM 2.0 client.

Pushes users from Authentik to Apple Business Manager via Apple's SCIM endpoint.
Uses externalId (Authentik PK) as the primary correlation key. Recovery of a
userName match without externalId requires an explicit operator opt-in.

Apple SCIM base URL: https://federation.apple.com/feeds/business/scim
Note: Apple's SCIM endpoint does not include /v2 in the public URL.

Sync strategy:
1. Read a complete standard SCIM listing, or preflight individual externalId
   and userName lookups when Apple returns its observed page-local metadata.
2. For each Authentik user:
   - Found (by either key), unchanged → skip (unchanged)
   - Found (by either key), changed  → PATCH changed attributes while preserving externalId
   - Not found → POST; on 409 → query by userName and reconcile only a safe match
3. Users present in Apple but absent from Authentik are left untouched;
   deactivate them in Authentik first (active=false propagates on next sync).

Individual lookups depend on Apple returning all matches to exact filters.
Apple's observed metadata cannot establish that guarantee.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, TypeGuard
from urllib.parse import quote

import httpx

from app.config import settings
from app.security.http_logging import response_metadata, safe_response_body_text
from app.security.pii import mask_email

logger = logging.getLogger(__name__)

APPLE_SCIM_BASE = "https://federation.apple.com/feeds/business/scim"
ABM_ACTIVITY_URL = "https://business.apple.com/main/activity"
_USER_LIST_COUNT = 200
_FILTER_LOOKUP_COUNT = 2


class AppleUserListError(Exception):
    """Apple's user listing could not be read completely and safely."""


class _AppleFilteredLookupRequired(AppleUserListError):
    """Apple's observed list metadata cannot establish directory completeness."""

    def __init__(self, by_external_id: dict[str, dict], by_username: dict[str, dict]) -> None:
        super().__init__("Apple SCIM listing requires individual identity lookups")
        self.by_external_id = by_external_id
        self.by_username = by_username


@dataclass
class SyncResult:
    """Counters returned after an Apple SCIM sync run."""

    created: int = 0
    updated: int = 0
    unchanged: int = 0
    conflicts: int = 0  # identity or creation conflicts requiring operator review
    errors: int = 0
    update_400_invalid_request: int = 0
    # Users with a real field diff outside the configured
    # APPLE_SCIM_UPDATE_MODE's scope (e.g. an email mismatch under
    # external_id_only) — permanently stale under this mode, not just
    # transiently unsynced. An overlay tag, not a separate bucket: counted
    # alongside whichever one of `updated`/`unchanged` already applies to
    # that user (a user can have both an actionable diff that gets patched
    # AND an unrelated out-of-scope one left over, e.g. under emails_only
    # with both an email and a name change).
    out_of_scope_diffs: int = 0
    conflict_usernames: list[str] = field(default_factory=list)


async def _fetch_users_page(client: httpx.AsyncClient, headers: dict, url: str) -> dict:
    """GET one page of the Apple SCIM users list or raise on an upstream failure."""
    try:
        resp = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise AppleUserListError("Network error listing Apple SCIM users") from exc
    if resp.status_code != 200:
        logger.error("Apple SCIM list users failed response=%s", response_metadata(resp))
        raise AppleUserListError(f"Apple SCIM user listing returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        logger.error("Apple SCIM list users returned non-JSON response=%s", response_metadata(resp))
        raise AppleUserListError("Apple SCIM user listing returned non-JSON") from exc
    if not isinstance(data, dict):
        raise AppleUserListError("Apple SCIM user listing returned an invalid response")
    return data


def _index_users_page(data: dict, by_ext_id: dict[str, dict], by_username: dict[str, dict]) -> None:
    """Index one page's Resources into the externalId/userName lookup dicts, in place."""
    for u in data.get("Resources", []):
        ext_id = u.get("externalId")
        if ext_id:
            by_ext_id[str(ext_id).strip()] = u
        username = u.get("userName", "")
        if username:
            by_username[_normalize_identifier(username)] = u


def _next_users_page_url(data: dict, *, expected_start: int = 1) -> str | None:
    """Return the next page URL, or None on the last page.

    Apple uses startIndex/itemsPerPage pagination (not cursor/next-link).
    """
    total = data["totalResults"]
    start = data.get("startIndex", expected_start)
    per_page = data.get("itemsPerPage", len(data.get("Resources", [])))
    if per_page == 0:
        if start <= total:
            raise AppleUserListError("Apple SCIM user listing ended before all users were returned")
        return None
    if start + per_page - 1 < total:
        return f"{APPLE_SCIM_BASE}/Users?count={_USER_LIST_COUNT}&startIndex={start + per_page}"
    return None


def _validate_users_page(data: dict, expected_start: int, expected_total: int | None) -> tuple[list[dict], int]:
    """Validate pagination metadata before any users from the page are used."""
    total = data.get("totalResults")
    start = data.get("startIndex", expected_start)
    resources = data.get("Resources", [])
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise AppleUserListError("Apple SCIM user listing has an invalid totalResults")
    if expected_total is not None and total != expected_total:
        raise AppleUserListError("Apple SCIM user listing changed during pagination")
    if not isinstance(start, int) or isinstance(start, bool) or start != expected_start:
        raise AppleUserListError("Apple SCIM user listing has an unexpected startIndex")
    if not isinstance(resources, list) or not all(isinstance(user, dict) for user in resources):
        raise AppleUserListError("Apple SCIM user listing has invalid Resources")
    per_page = data.get("itemsPerPage", len(resources))
    if not isinstance(per_page, int) or isinstance(per_page, bool) or per_page != len(resources):
        raise AppleUserListError("Apple SCIM user listing has an invalid itemsPerPage")
    if start - 1 + len(resources) > total:
        raise AppleUserListError("Apple SCIM user listing exceeds totalResults")
    if not resources and start <= total:
        raise AppleUserListError("Apple SCIM user listing ended before all users were returned")
    return resources, total


def _is_safe_user_id(value: object) -> TypeGuard[str]:
    """Reject identifiers that cannot safely identify a single user URL segment."""
    return (
        isinstance(value, str)
        and value == value.strip()
        and value not in ("", ".", "..")
        and not any(char in value for char in ("/", "\\", "%"))
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _user_url(user_id: str) -> str:
    return f"{APPLE_SCIM_BASE}/Users/{quote(user_id, safe='')}"


def _index_unique_user(
    user: dict, seen_ids: set[str], by_ext_id: dict[str, dict], by_username: dict[str, dict]
) -> None:
    """Reject ambiguous identities before adding one listed user to the indexes."""
    user_id = user.get("id")
    username = user.get("userName")
    if not _is_safe_user_id(user_id):
        raise AppleUserListError("Apple SCIM user listing contains a user with an invalid id")
    if not isinstance(username, str) or not username.strip():
        raise AppleUserListError("Apple SCIM user listing contains a user without a userName")
    external_id = str(user.get("externalId") or "").strip()
    normalized_username = _normalize_identifier(username)
    if user_id in seen_ids or normalized_username in by_username or (external_id and external_id in by_ext_id):
        raise AppleUserListError("Apple SCIM user listing contains duplicate identities")
    seen_ids.add(user_id)
    _index_users_page({"Resources": [user]}, by_ext_id, by_username)


def _apple_single_page(data: dict, requested_count: int) -> list[dict] | None:
    """Recognize Apple's observed count-relative index and requested-count metadata."""
    resources = data.get("Resources")
    total = data.get("totalResults")
    start = data.get("startIndex")
    per_page = data.get("itemsPerPage")
    if (
        not isinstance(resources, list)
        or type(total) is not int
        or type(start) is not int
        or type(per_page) is not int
        or total != len(resources)
        or start != len(resources) + 1
        or per_page != requested_count
    ):
        return None
    if len(resources) > requested_count:
        raise AppleUserListError("Apple SCIM user listing exceeds the requested count")
    normalized = {**data, "startIndex": 1, "itemsPerPage": len(resources)}
    users, _ = _validate_users_page(normalized, expected_start=1, expected_total=None)
    return users


def _index_user_list(users: list[dict]) -> tuple[dict[str, dict], dict[str, dict]]:
    """Build unique externalId and userName indexes for an Apple listing."""
    by_ext_id: dict[str, dict] = {}
    by_username: dict[str, dict] = {}
    seen_ids: set[str] = set()
    for user in users:
        _index_unique_user(user, seen_ids, by_ext_id, by_username)
    return by_ext_id, by_username


async def _get_existing_users(client: httpx.AsyncClient, headers: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    """Return an Apple user listing indexed by externalId and userName.

    Raise AppleUserListError when an incomplete or inconsistent listing is detected.
    """
    by_ext_id: dict[str, dict] = {}
    by_username: dict[str, dict] = {}
    seen_ids: set[str] = set()
    expected_start = 1
    expected_total: int | None = None
    url: str | None = f"{APPLE_SCIM_BASE}/Users?count={_USER_LIST_COUNT}"
    while url:
        data = await _fetch_users_page(client, headers, url)
        if expected_total is None:
            apple_users = _apple_single_page(data, _USER_LIST_COUNT)
            if apple_users is not None:
                raise _AppleFilteredLookupRequired(*_index_user_list(apple_users))
        users, total = _validate_users_page(data, expected_start, expected_total)
        expected_total = total
        for user in users:
            _index_unique_user(user, seen_ids, by_ext_id, by_username)
        url = _next_users_page_url(data, expected_start=expected_start)
        expected_start += len(users)
    return by_ext_id, by_username


def _filtered_resources(data: dict) -> list[dict]:
    """Validate filtered response metadata and return at most one resource."""
    total = data.get("totalResults")
    if type(total) is not int or total < 0:
        raise AppleUserListError("Apple SCIM filtered lookup has an invalid totalResults")
    start = data.get("startIndex", 1)
    if type(start) is not int or start not in (0, 1):
        raise AppleUserListError("Apple SCIM filtered lookup has an invalid startIndex")
    resources = data.get("Resources", [] if total == 0 else None)
    if not isinstance(resources, list) or not all(isinstance(item, dict) for item in resources):
        raise AppleUserListError("Apple SCIM filtered lookup has invalid Resources")
    per_page = data.get("itemsPerPage", len(resources))
    if type(per_page) is not int or per_page != len(resources) or total != len(resources):
        raise AppleUserListError("Apple SCIM filtered lookup has inconsistent result counts")
    if total > 1:
        raise AppleUserListError("Apple SCIM filtered lookup returned multiple matching users")
    return resources


def _validate_filtered_user(data: dict, attribute: str, expected: str) -> dict | None:
    """Validate an exact-match response before using it as identity evidence."""
    resources = _filtered_resources(data)
    if not resources:
        return None

    user = resources[0]
    if not _is_safe_user_id(user.get("id")):
        raise AppleUserListError("Apple SCIM filtered lookup has an invalid user id")
    username = user.get("userName")
    if not isinstance(username, str) or not username.strip() or not isinstance(user.get("name", {}), dict):
        raise AppleUserListError("Apple SCIM filtered lookup has invalid user attributes")
    actual = user.get(attribute)
    if attribute == "userName":
        matches = _normalize_identifier(actual) == _normalize_identifier(expected)
    else:
        matches = str(actual or "").strip() == expected
    if not matches:
        raise AppleUserListError("Apple SCIM filtered lookup returned a mismatched identity")
    return user


def _same_identity(first: dict | None, second: dict | None) -> bool:
    """Compare only stable identity fields, not mutable profile attributes."""
    if first is None or second is None:
        return first is second
    return (
        first.get("id") == second.get("id")
        and _normalize_identifier(first.get("userName")) == _normalize_identifier(second.get("userName"))
        and str(first.get("externalId") or "").strip() == str(second.get("externalId") or "").strip()
    )


def _source_identities(scim_users: list[dict]) -> list[tuple[str, str]]:
    """Validate source identities before looking up or modifying Apple users."""
    identities: list[tuple[str, str]] = []
    seen_external_ids: set[str] = set()
    seen_usernames: set[str] = set()
    for user in scim_users:
        external_id = str(user.get("externalId") or "").strip()
        username = user.get("userName")
        if not external_id or not isinstance(username, str) or not username.strip():
            raise AppleUserListError("Authentik SCIM user has an invalid identity")
        normalized_username = _normalize_identifier(username)
        if external_id in seen_external_ids or normalized_username in seen_usernames:
            raise AppleUserListError("Authentik SCIM users contain duplicate identities")
        seen_external_ids.add(external_id)
        seen_usernames.add(normalized_username)
        identities.append((external_id, username))
    return identities


async def _lookup_filtered_user(
    client: httpx.AsyncClient, headers: dict, attribute: str, value: str, sampled: dict | None
) -> dict | None:
    """Look up one identity and reject disagreement with the initial sample."""
    literal = quote(json.dumps(value, ensure_ascii=False), safe="")
    url = f"{APPLE_SCIM_BASE}/Users?filter={attribute}%20eq%20{literal}&count={_FILTER_LOOKUP_COUNT}"
    data = await _fetch_users_page(client, headers, url)
    found = _validate_filtered_user(data, attribute, value)
    if sampled is not None and not _same_identity(sampled, found):
        raise AppleUserListError("Apple SCIM filtered lookup disagrees with the initial listing")
    return found


def _record_filtered_identity(by_id: dict[str, dict], found: dict | None) -> None:
    """Reject inconsistent filter results that claim the same Apple user ID."""
    if found is None:
        return
    previous = by_id.get(found["id"])
    if previous is not None and not _same_identity(previous, found):
        raise AppleUserListError("Apple SCIM filtered lookups disagree about a user")
    by_id[found["id"]] = found


async def _get_existing_users_by_filter(
    client: httpx.AsyncClient,
    headers: dict,
    scim_users: list[dict],
    sample: _AppleFilteredLookupRequired,
) -> tuple[dict[str, dict], dict[str, dict]]:
    """Preflight every source identity before making any Apple user writes."""
    by_id: dict[str, dict] = {}
    results: list[tuple[str, str, dict | None, dict | None]] = []
    for external_id, username in _source_identities(scim_users):
        external_match = await _lookup_filtered_user(
            client, headers, "externalId", external_id, sample.by_external_id.get(external_id)
        )
        username_match = await _lookup_filtered_user(
            client, headers, "userName", username, sample.by_username.get(_normalize_identifier(username))
        )
        _record_filtered_identity(by_id, external_match)
        _record_filtered_identity(by_id, username_match)
        results.append((external_id, username, external_match, username_match))

    by_external_id: dict[str, dict] = {}
    by_username: dict[str, dict] = {}
    seen_ids: set[str] = set()
    for user_id, filtered in by_id.items():
        verified = await _fetch_users_page(client, headers, _user_url(user_id))
        if not _same_identity(filtered, verified) or not isinstance(verified.get("name", {}), dict):
            raise AppleUserListError("Apple SCIM user identity changed during lookup verification")
        _index_unique_user(verified, seen_ids, by_external_id, by_username)

    for external_id, username, external_match, username_match in results:
        if not _same_identity(external_match, by_external_id.get(external_id)) or not _same_identity(
            username_match, by_username.get(_normalize_identifier(username))
        ):
            raise AppleUserListError("Apple SCIM filtered lookups returned inconsistent identities")
    return by_external_id, by_username


def _normalize_identifier(value: object) -> str:
    """Normalize a SCIM identifier for stable semantic comparisons."""
    return str(value or "").strip().lower()


def _normalize_email(value: object) -> str:
    """Normalize an email address for comparison without changing payloads sent to Apple."""
    return str(value or "").strip().lower()


def _scim_log_username(username: str | None) -> str:
    """Return a log-safe userName, masked unless SSF_LOG_PII is enabled."""
    return mask_email(
        username or "",
        log_pii=settings.log_pii,
        pii_key=settings.pii_pepper or settings.ssf_management_token,
    )


def _format_changed_fields(diffs: dict[str, bool]) -> str:
    """Format field diffs for human-readable logs (e.g. ``email, active``)."""
    return ", ".join(name for name, changed in diffs.items() if changed) or "none"


def _log_user_ref(user: dict) -> str:
    """Compact user reference for log lines: ``pk=45 user=filip@...``."""
    return f"pk={user.get('externalId')} user={_scim_log_username(user.get('userName'))}"


def _can_recover_by_username(apple_user: dict, authentik_external_id: object) -> bool:
    """Return whether a userName match may be reconciled with this Authentik user.

    An existing matching externalId is sufficient. A missing one requires
    explicit opt-in; a different or missing Authentik externalId is rejected.
    """
    found_ext = str(apple_user.get("externalId") or "").strip()
    current_ext = str(authentik_external_id or "").strip()
    if not current_ext:
        return False
    if found_ext:
        return found_ext == current_ext
    return settings.apple_scim_allow_username_recovery


def _record_username_conflict(result: SyncResult, user: dict, reason: str) -> None:
    """Record a conflict without guessing its cause or writing to the account."""
    result.conflicts += 1
    username = user.get("userName")
    if isinstance(username, str) and username:
        result.conflict_usernames.append(username)
    logger.warning("Apple SCIM: ⚠️  %s — USERNAME_CONFLICT: %s", _log_user_ref(user), reason)


def _primary_email(user: dict) -> str | None:
    """Return the primary email address from a SCIM user dict.

    Apple may omit the ``primary`` flag from GET responses even though we send
    ``"primary": true`` on POST/PUT (RFC 7643 allows servers to omit optional
    attributes).  When no entry with ``primary: true`` is found, fall back to
    the first email in the list so the comparison does not produce a spurious
    mismatch on every sync cycle.  Malformed entries are ignored safely.
    """
    emails = user.get("emails", [])
    if isinstance(emails, dict):
        emails = [emails]
    if not isinstance(emails, list):
        return None

    first_value: str | None = None
    for email in emails:
        if not isinstance(email, dict):
            continue
        value = email.get("value")
        if first_value is None and value:
            first_value = str(value).strip()
        if email.get("primary") is True and value:
            return str(value).strip()
    return first_value


def _field_diffs(existing: dict, new: dict, *, include_external_id: bool = True) -> dict[str, bool]:
    """Return normalized syncable-field differences between Apple and Authentik users."""
    diffs = {
        "userName": _normalize_identifier(existing.get("userName")) != _normalize_identifier(new.get("userName")),
        "givenName": str(existing.get("name", {}).get("givenName") or "").strip()
        != str(new.get("name", {}).get("givenName") or "").strip(),
        "familyName": str(existing.get("name", {}).get("familyName") or "").strip()
        != str(new.get("name", {}).get("familyName") or "").strip(),
        "active": bool(existing.get("active", True)) != bool(new.get("active", True)),
        "email": _normalize_email(_primary_email(existing)) != _normalize_email(_primary_email(new)),
    }
    if include_external_id:
        diffs["externalId"] = str(existing.get("externalId") or "").strip() != str(new.get("externalId") or "").strip()
    return diffs


def _users_differ(existing: dict, new: dict) -> bool:
    """Return True if any syncable field has changed after semantic normalization."""
    diffs = _field_diffs(existing, new)
    if any(diffs.values()):
        logger.debug(
            "Apple SCIM: diff %s — changed: %s",
            _log_user_ref(new),
            _format_changed_fields(diffs),
        )
        return True
    return False


def _classify_update_400(response: httpx.Response) -> bool:
    """Return True when an Apple 400 likely represents an invalid update request."""
    if response.status_code != 400:
        return False
    try:
        payload = response.json()
    except Exception:
        return True
    if isinstance(payload, dict) and (payload.get("scimType") or payload.get("detail") or payload.get("status")):
        return True
    return True


def _update_fields_for_mode(mode: str) -> list[str]:
    """Return the requested field set for the configured update experiment."""
    if mode == "external_id_only":
        return ["externalId"]
    if mode == "emails_only":
        return ["emails"]
    if mode == "username_only":
        return ["userName"]
    if mode == "replace_all":
        return ["externalId", "userName", "name", "emails", "active"]
    return ["externalId", "userName", "name", "emails", "active"]


# Maps _update_fields_for_mode()'s SCIM field names to _field_diffs()'s
# (differently-named, and for "name" split-in-two) diff-dict keys.
_MODE_FIELD_TO_DIFF_KEYS: dict[str, tuple[str, ...]] = {
    "externalId": ("externalId",),
    "userName": ("userName",),
    "name": ("givenName", "familyName"),
    "emails": ("email",),
    "active": ("active",),
}


def _actionable_diffs(diffs: dict[str, bool], mode: str) -> dict[str, bool]:
    """Filter `diffs` to only the fields `_patch_user()` will actually write under `mode`.

    A diff outside a narrow mode's scope (e.g. an email mismatch under
    "external_id_only") can never be resolved by the PATCH that mode sends —
    treating it as actionable would call _patch_user() every sync cycle,
    which writes only the in-scope fields and leaves the real diff
    unresolved, forever re-triggering the same no-op update next cycle.
    """
    allowed_keys: set[str] = set()
    for field_name in _update_fields_for_mode(mode):
        allowed_keys.update(_MODE_FIELD_TO_DIFF_KEYS.get(field_name, ()))
    return {key: value for key, value in diffs.items() if key in allowed_keys}


def _changed_name_operations(user: dict, diffs: dict[str, bool]) -> list[dict[str, Any]]:
    """Build individual name-subattribute PATCH operations for changed fields."""
    return [
        {"op": "Replace", "path": f"name.{subfield}", "value": user.get("name", {}).get(subfield, "")}
        for subfield in _MODE_FIELD_TO_DIFF_KEYS["name"]
        if diffs.get(subfield, False)
    ]


def _build_update_request(
    user: dict, mode: str, apple_id: str, *, diffs: dict[str, bool]
) -> tuple[str, dict[str, Any], list[str]]:
    """Build the outbound Apple SCIM update request for the configured mode."""
    fields = _update_fields_for_mode(mode)
    if mode == "replace_all":
        # Apple rejects PUT bodies that include `externalId` (immutable
        # after creation) or omit the resource `id` — send everything else
        # from `user` plus the Apple-assigned id, not the raw dict.
        put_body = {k: v for k, v in user.items() if k != "externalId"}
        put_body["id"] = apple_id
        return "PUT", put_body, [name for name in fields if name != "externalId"]

    fields = [name for name in fields if any(diffs.get(key, False) for key in _MODE_FIELD_TO_DIFF_KEYS[name])]
    if not fields:
        raise ValueError("Cannot build a PATCH without changed attributes")

    operations: list[dict[str, Any]] = []
    patch_fields: list[str] = []
    for field_name in fields:
        if field_name == "name":
            name_operations = _changed_name_operations(user, diffs)
            operations.extend(name_operations)
            patch_fields.extend(operation["path"] for operation in name_operations)
            continue
        if field_name == "externalId":
            value: Any = str(user.get("externalId") or "").strip()
        elif field_name == "userName":
            value = user.get("userName")
        elif field_name == "emails":
            value = user.get("emails", [])
        else:
            value = user.get("active", True)
        operations.append({"op": "Replace", "path": field_name, "value": value})
        patch_fields.append(field_name)
    return (
        "PATCH",
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": operations,
        },
        patch_fields,
    )


def _log_update_failure(
    *,
    operation: str,
    http_method: str,
    response: httpx.Response,
    user: dict,
    changed_fields: list[str],
    apple_id: str | None = None,
) -> None:
    """Log Apple SCIM write failures with stable, PII-safe diagnostics."""
    body = None
    if settings.apple_scim_log_error_body:
        body = safe_response_body_text(
            response,
            log_pii=settings.log_pii,
            pii_key=settings.pii_pepper or settings.ssf_management_token,
        )
    logger.warning(
        "Apple SCIM: %s failed operation=%s externalId=%s appleId=%s userName=%s "
        "fields=%s endpoint=/Users/%s method=%s status=%s response=%s redacted_body=%s",
        operation,
        operation,
        user.get("externalId"),
        apple_id,
        _scim_log_username(user.get("userName")),
        changed_fields,
        apple_id or "",
        http_method,
        response.status_code,
        response_metadata(response),
        body,
    )


async def _patch_user(
    client: httpx.AsyncClient,
    headers: dict,
    apple_user: dict,
    new_user: dict,
    result: SyncResult,
    *,
    diffs: dict[str, bool],
    label: str = "",
) -> None:
    """PATCH a user update. Shared by normal update path and 409-recovery path."""
    apple_id = apple_user["id"]
    method, update_body, changed_fields = _build_update_request(
        new_user, settings.apple_scim_update_mode, apple_id, diffs=diffs
    )
    if method == "PUT":
        resp = await client.put(_user_url(apple_id), json=update_body, headers=headers)
    else:
        resp = await client.patch(_user_url(apple_id), json=update_body, headers=headers)
    if resp.status_code in (200, 204):
        result.updated += 1
        logger.info(
            "Apple SCIM: updated %s%s mode=%s fields=%s",
            _log_user_ref(new_user),
            f" ({label})" if label else "",
            settings.apple_scim_update_mode,
            changed_fields,
        )
    else:
        result.errors += 1
        if _classify_update_400(resp):
            result.update_400_invalid_request += 1
        _log_update_failure(
            operation="update",
            http_method=method,
            response=resp,
            user=new_user,
            changed_fields=changed_fields,
            apple_id=apple_id,
        )


async def _patch_external_id(
    client: httpx.AsyncClient,
    headers: dict,
    apple_user: dict,
    new_user: dict,
    result: SyncResult,
) -> bool:
    """Patch the Apple SCIM externalId when a user was recovered by userName."""
    apple_id = apple_user["id"]
    external_id = str(new_user.get("externalId") or "").strip()
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "path": "externalId", "value": external_id}],
    }
    resp = await client.patch(_user_url(apple_id), json=body, headers=headers)
    if resp.status_code in (200, 204):
        try:
            verification = await client.get(_user_url(apple_id), headers=headers)
        except httpx.HTTPError as exc:
            result.errors += 1
            logger.warning(
                "Apple SCIM: externalId repair verification failed for %s: %s",
                _log_user_ref(new_user),
                type(exc).__name__,
            )
            return False
        if verification.status_code != 200:
            result.errors += 1
            logger.warning(
                "Apple SCIM: externalId repair verification failed for %s: HTTP %s",
                _log_user_ref(new_user),
                verification.status_code,
            )
            return False
        try:
            verified = verification.json()
        except ValueError:
            verified = None
        if (
            not isinstance(verified, dict)
            or verified.get("id") != apple_id
            or str(verified.get("externalId") or "").strip() != external_id
            or _normalize_identifier(verified.get("userName")) != _normalize_identifier(new_user.get("userName"))
            or not isinstance(verified.get("name", {}), dict)
        ):
            result.errors += 1
            logger.warning("Apple SCIM: externalId repair could not be verified for %s", _log_user_ref(new_user))
            return False
        verified_user = dict(verified)
        apple_user.clear()
        apple_user.update(verified_user)
        result.updated += 1
        logger.info(
            "Apple SCIM: linked %s to appleId=%s (externalId repair)",
            _log_user_ref(new_user),
            apple_id,
        )
        return True
    result.errors += 1
    if _classify_update_400(resp):
        result.update_400_invalid_request += 1
    _log_update_failure(
        operation="external_id_repair",
        http_method="PATCH",
        response=resp,
        user=new_user,
        changed_fields=["externalId"],
        apple_id=apple_id,
    )
    return False


async def _query_username_filter(
    client: httpx.AsyncClient, headers: dict, username: str, safe_username: str
) -> dict | None:
    """Query Apple SCIM for filter=userName eq "...". Return the JSON payload, or None on any failure (logged)."""
    # SCIM RFC 7644 filter literals use double quotes (not single quotes from repr())
    scim_filter = quote(json.dumps(username, ensure_ascii=False), safe="")
    filter_url = f"{APPLE_SCIM_BASE}/Users?filter=userName%20eq%20{scim_filter}&count={_FILTER_LOOKUP_COUNT}"
    try:
        resp = await client.get(filter_url, headers=headers)
    except httpx.HTTPError:
        logger.warning("Apple SCIM: 409-recovery network error for userName=%s", safe_username)
        return None
    if resp.status_code != 200:
        logger.warning(
            "Apple SCIM: 409-recovery filter query failed status=%s userName=%s", resp.status_code, safe_username
        )
        return None
    try:
        payload = resp.json()
    except ValueError:
        logger.warning(
            "Apple SCIM: 409-recovery filter query returned non-JSON response=%s",
            response_metadata(resp),
        )
        return None
    if not isinstance(payload, dict):
        logger.warning("Apple SCIM: 409-recovery filter query returned an invalid response")
        return None
    return payload


def _username_recovery_allowed(apple_user: dict, user: dict, result: SyncResult) -> bool:
    """Record unsafe username matches and warn when unlinked recovery is enabled."""
    if _can_recover_by_username(apple_user, user.get("externalId")):
        if not str(apple_user.get("externalId") or "").strip():
            logger.warning("Apple SCIM: username-only recovery explicitly enabled for %s", _log_user_ref(user))
        return True
    if not str(user.get("externalId") or "").strip():
        reason = "Authentik user has no externalId"
    elif str(apple_user.get("externalId") or "").strip():
        reason = "matched Apple record has an externalId belonging to a different user"
    else:
        reason = "matched Apple record has no externalId; username-only recovery is disabled"
    _record_username_conflict(result, user, reason)
    return False


async def _reconcile_diffs(
    client: httpx.AsyncClient,
    headers: dict,
    apple_user: dict,
    user: dict,
    result: SyncResult,
    *,
    recovered_by_username: bool,
    patch_label: str | None = None,
) -> None:
    """Diff `apple_user` against `user` and PATCH any actionable changes.

    Shared by the normal sync_users() reconciliation path and the _handle_409
    userName-recovery path (which always passes recovered_by_username=True,
    since by construction that user was only found via the userName filter).
    `patch_label`, when given, is used verbatim as _patch_user()'s log label
    and suppresses the update/unchanged progress debug logs — matching the
    409-recovery path's original quieter behavior. Leave it None (the
    sync_users() path) to derive the label from the actionable diffs and
    emit those debug logs.
    """
    if recovered_by_username and not _username_recovery_allowed(apple_user, user, result):
        return

    diffs = _field_diffs(apple_user, user)
    external_id_patch_attempted = False
    # Repair unconditionally once recovered by username, not
    # only when externalId is the sole diff: under replace_all
    # mode the PUT below never includes externalId (Apple
    # rejects it there), and narrow single-field modes
    # (emails_only, username_only) never include it either —
    # so if this were gated on "no other diff", a user missing
    # externalId AND some other field would have their linkage
    # stay broken for another whole sync cycle.
    if recovered_by_username and diffs.get("externalId"):
        external_id_patch_attempted = True
        if not await _patch_external_id(client, headers, apple_user, user, result):
            return
        diffs = _field_diffs(apple_user, user, include_external_id=False)
    actionable = _actionable_diffs(diffs, settings.apple_scim_update_mode)
    # Computed independently of whether an actionable update
    # also happens below — a user can have BOTH (e.g. under
    # emails_only, an email diff gets patched while a name
    # diff is out of scope); nesting this inside the "no
    # actionable diff" branch would silently drop the report
    # for that user until a later sync sees only the
    # out-of-scope field left.
    if any(v for k, v in diffs.items() if k not in actionable):
        result.out_of_scope_diffs += 1
        logger.debug(
            "Apple SCIM: %s has a diff outside update_mode=%s scope — changed: %s",
            _log_user_ref(user),
            settings.apple_scim_update_mode,
            _format_changed_fields(diffs),
        )
    if any(actionable.values()):
        label = patch_label if patch_label is not None else _format_changed_fields(actionable)
        if patch_label is None:
            logger.debug("Apple SCIM: update %s — changed: %s", _log_user_ref(user), label)
        await _patch_user(client, headers, apple_user, user, result, diffs=actionable, label=label)
    elif not external_id_patch_attempted:
        # A successfully repaired linkage was already counted as updated.
        result.unchanged += 1
        if patch_label is None:
            logger.debug("Apple SCIM: unchanged %s", _log_user_ref(user))


async def _verified_filtered_user(
    client: httpx.AsyncClient, headers: dict, username: str, found: dict, user: dict
) -> dict | None:
    """Return a freshly verified user when it agrees with the filter result."""
    try:
        try:
            _, listed_by_username = await _get_existing_users(client, headers)
        except _AppleFilteredLookupRequired as sample:
            _, listed_by_username = await _get_existing_users_by_filter(client, headers, [user], sample)
    except AppleUserListError as exc:
        logger.warning("Apple SCIM: 409-recovery could not verify the user identity: %s", exc)
        return None
    listed = listed_by_username.get(_normalize_identifier(username))
    if (
        listed is None
        or listed["id"] != found["id"]
        or str(listed.get("externalId") or "").strip() != str(found.get("externalId") or "").strip()
    ):
        logger.warning("Apple SCIM: 409-recovery identity disagrees with the verified user")
        return None
    return listed


async def _handle_409(
    client: httpx.AsyncClient,
    headers: dict,
    user: dict,
    result: SyncResult,
) -> None:
    """Resolve a create conflict only when the username lookup identifies an eligible account."""
    username = user.get("userName", "")
    # Mask the email address per SSF_LOG_PII setting so it does not leak
    # into production logs when privacy mode is active.
    safe_username = mask_email(
        username, log_pii=settings.log_pii, pii_key=settings.pii_pepper or settings.ssf_management_token
    )
    payload = await _query_username_filter(client, headers, username, safe_username)
    if payload is None:
        result.errors += 1
        return
    zero_based = type(payload.get("startIndex")) is int and payload["startIndex"] == 0
    if zero_based:
        payload = {**payload, "startIndex": 1}
    try:
        resources, total = _validate_users_page(payload, expected_start=1, expected_total=None)
    except AppleUserListError:
        result.errors += 1
        logger.warning("Apple SCIM: 409-recovery filter query returned an invalid user listing")
        return
    if total > 1:
        _record_username_conflict(result, user, "multiple Apple accounts match the username")
        return
    if total == 0:
        _record_username_conflict(result, user, "no matching Apple user found after a create conflict; review ABM")
        return

    found = resources[0]
    apple_id = found.get("id")
    found_username = found.get("userName")
    if (
        not _is_safe_user_id(apple_id)
        or not isinstance(found_username, str)
        or not found_username.strip()
        or _normalize_identifier(found_username) != _normalize_identifier(username)
    ):
        result.errors += 1
        logger.warning("Apple SCIM: 409-recovery filter returned an invalid or mismatched identity")
        return
    if zero_based:
        verified = await _verified_filtered_user(client, headers, username, found, user)
        if verified is None:
            result.errors += 1
            return
        found = verified
    await _reconcile_diffs(client, headers, found, user, result, recovered_by_username=True, patch_label="409-recovery")


def _match_apple_user(
    user: dict, by_ext_id: dict[str, dict], by_username: dict[str, dict]
) -> tuple[dict | None, bool, bool]:
    """Return the match, whether it used username, and whether the two keys conflict."""
    ext_id = str(user["externalId"]).strip()
    by_ext = by_ext_id.get(ext_id)
    username_match = by_username.get(_normalize_identifier(user.get("userName")))
    if by_ext is not None:
        if username_match is not None and username_match["id"] != by_ext["id"]:
            return None, False, True
        return by_ext, False, False

    if username_match:
        return username_match, True, False
    return None, False, False


async def _verify_created_user(client: httpx.AsyncClient, headers: dict, user: dict, response: httpx.Response) -> bool:
    """Check a created user against both identity filters and a direct read."""
    try:
        created = response.json()
    except ValueError:
        created = None
    created_id = created.get("id") if isinstance(created, dict) else None
    if not _is_safe_user_id(created_id):
        logger.warning(
            "Apple SCIM: create may have succeeded for %s but returned no verifiable user id", _log_user_ref(user)
        )
        return False
    try:
        by_external_id, by_username = await _get_existing_users_by_filter(
            client, headers, [user], _AppleFilteredLookupRequired({}, {})
        )
    except AppleUserListError as exc:
        logger.warning(
            "Apple SCIM: create may have succeeded for %s but identity verification failed: %s",
            _log_user_ref(user),
            exc,
        )
        return False
    external_match = by_external_id.get(str(user["externalId"]).strip())
    username_match = by_username.get(_normalize_identifier(user.get("userName")))
    if (
        external_match is None
        or not _same_identity(external_match, username_match)
        or external_match["id"] != created_id
    ):
        logger.warning(
            "Apple SCIM: create may have succeeded for %s but the returned identity could not be verified",
            _log_user_ref(user),
        )
        return False
    return True


async def _create_user(
    client: httpx.AsyncClient, headers: dict, user: dict, result: SyncResult, *, verify_identity: bool = False
) -> None:
    """POST a brand-new user to Apple SCIM, delegating 409s to the userName-recovery path."""
    resp = await client.post(f"{APPLE_SCIM_BASE}/Users", json=user, headers=headers)
    if resp.status_code in (200, 201):
        if verify_identity and not await _verify_created_user(client, headers, user, resp):
            result.errors += 1
            return
        result.created += 1
        logger.info("Apple SCIM: created %s", _log_user_ref(user))
    elif resp.status_code == 409:
        await _handle_409(client, headers, user, result)
    else:
        result.errors += 1
        _log_update_failure(
            operation="create",
            http_method="POST",
            response=resp,
            user=user,
            changed_fields=["externalId", "userName", "name", "emails", "active"],
        )


def _log_sync_start(scim_users: list[dict], by_ext_id: dict, by_username: dict, *, filtered: bool = False) -> None:
    """Log source and matched-user counts without exposing individual identities."""
    # Count users that will be recovered via userName fallback — mirrors the
    # sync loop condition exactly: externalId miss AND username match has no
    # externalId of its own (so we won't overwrite an unrelated record).
    recovered = sum(
        1
        for u in scim_users
        if not by_ext_id.get(str(u["externalId"]).strip())
        and (m := by_username.get(_normalize_identifier(u.get("userName")))) is not None
        and _can_recover_by_username(m, u["externalId"])
    )
    logger.info(
        "Apple SCIM: sync start — %s=%d linked_by_external_id=%d email_recovery=%d authentik=%d update_mode=%s",
        "apple_matched" if filtered else "apple",
        len(by_username),
        len(by_ext_id),
        recovered,
        len(scim_users),
        settings.apple_scim_update_mode,
    )


def _log_sync_summary(result: SyncResult) -> None:
    """Summarize sync outcomes and flag accounts needing operator review."""
    logger.info(
        "Apple SCIM: sync done — created=%d updated=%d unchanged=%d conflicts=%d "
        "errors=%d update_400_invalid_request=%d out_of_scope_diffs=%d",
        result.created,
        result.updated,
        result.unchanged,
        result.conflicts,
        result.errors,
        result.update_400_invalid_request,
        result.out_of_scope_diffs,
    )
    if result.conflicts > 0:
        logger.warning(
            "Apple SCIM: ⚠️  %d account(s) require identity or creation-conflict review — go to %s",
            result.conflicts,
            ABM_ACTIVITY_URL,
        )
    if result.out_of_scope_diffs > 0:
        logger.warning(
            "Apple SCIM: ⚠️  %d user(s) have a field diff outside update_mode=%s scope and will stay "
            "stale — widen APPLE_SCIM_UPDATE_MODE or fix manually in Apple Business Manager",
            result.out_of_scope_diffs,
            settings.apple_scim_update_mode,
        )


async def sync_users(access_token: str, scim_users: list[dict]) -> SyncResult:
    """Upsert Authentik users into Apple Business Manager."""
    result = SyncResult()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/scim+json",
        "Accept": "application/scim+json",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        filtered = False
        try:
            by_ext_id, by_username = await _get_existing_users(client, headers)
        except _AppleFilteredLookupRequired as sample:
            by_ext_id, by_username = await _get_existing_users_by_filter(client, headers, scim_users, sample)
            filtered = True
        _log_sync_start(scim_users, by_ext_id, by_username, filtered=filtered)

        for user in scim_users:
            ext_id = user["externalId"]
            apple_user, recovered_by_username, username_conflict = _match_apple_user(user, by_ext_id, by_username)
            if username_conflict:
                _record_username_conflict(result, user, "username belongs to a different Apple account")
                continue

            try:
                if apple_user is None:
                    await _create_user(client, headers, user, result, verify_identity=filtered)
                else:
                    await _reconcile_diffs(
                        client, headers, apple_user, user, result, recovered_by_username=recovered_by_username
                    )
            except httpx.HTTPError:
                result.errors += 1
                logger.exception("Apple SCIM: network error for externalId=%s", ext_id)

    _log_sync_summary(result)
    return result
