"""Apple SCIM 2.0 client.

Pushes users from Authentik to Apple Business Manager via Apple's SCIM endpoint.
Uses externalId (Authentik PK) as the primary correlation key; userName (email)
is a fallback for users whose externalId is missing and needs one PATCH repair.

Apple SCIM base URL: https://federation.apple.com/feeds/business/scim
Note: Apple's SCIM endpoint does not include /v2 in the public URL.

Sync strategy (Authentik pattern):
1. GET all existing Apple users → index by externalId (primary) and userName (fallback)
2. For each Authentik user:
   - Found (by either key), unchanged → skip (unchanged)
   - Found (by either key), changed  → PATCH changed attributes while preserving externalId
   - Not found → POST; on 409 → query filter=userName eq "..." then PATCH
3. Users present in Apple but absent from Authentik are left untouched;
   deactivate them in Authentik first (active=false propagates on next sync).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

from app.config import settings
from app.security.http_logging import response_metadata, safe_response_body_text
from app.security.pii import mask_email

logger = logging.getLogger(__name__)

APPLE_SCIM_BASE = "https://federation.apple.com/feeds/business/scim"
ABM_ACTIVITY_URL = "https://business.apple.com/main/activity"


@dataclass
class SyncResult:
    """Counters returned after an Apple SCIM sync run."""

    created: int = 0
    updated: int = 0
    unchanged: int = 0
    conflicts: int = 0  # users that exist but have a personal Apple ID conflict
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


async def _fetch_users_page(client: httpx.AsyncClient, headers: dict, url: str) -> dict | None:
    """GET one page of the Apple SCIM users list, or None on any upstream failure (logged)."""
    resp = await client.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error("Apple SCIM list users failed response=%s", response_metadata(resp))
        return None
    try:
        return resp.json()
    except Exception:
        logger.error("Apple SCIM list users returned non-JSON response=%s", response_metadata(resp))
        return None


def _index_users_page(data: dict, by_ext_id: dict[str, dict], by_username: dict[str, dict]) -> None:
    """Index one page's Resources into the externalId/userName lookup dicts, in place."""
    for u in data.get("Resources", []):
        ext_id = u.get("externalId")
        if ext_id:
            by_ext_id[str(ext_id).strip()] = u
        username = u.get("userName", "")
        if username:
            by_username[_normalize_identifier(username)] = u


def _next_users_page_url(data: dict) -> str | None:
    """Return the next page URL, or None on the last page.

    Apple uses startIndex/itemsPerPage pagination (not cursor/next-link).
    """
    total = data.get("totalResults", 0)
    start = data.get("startIndex", 1)
    per_page = data.get("itemsPerPage") or len(data.get("Resources", []))
    if per_page == 0:
        return None  # guard: empty page with totalResults > 0 would loop forever
    if start + per_page - 1 < total:
        return f"{APPLE_SCIM_BASE}/Users?count=200&startIndex={start + per_page}"
    return None


async def _get_existing_users(client: httpx.AsyncClient, headers: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    """Return all Apple SCIM users indexed by externalId AND by userName.

    Returns:
        (by_ext_id, by_username) — two dicts for primary and fallback lookup.
        by_username keys are lowercased for case-insensitive matching.
    """
    by_ext_id: dict[str, dict] = {}
    by_username: dict[str, dict] = {}
    url: str | None = f"{APPLE_SCIM_BASE}/Users?count=200"
    while url:
        data = await _fetch_users_page(client, headers, url)
        if data is None:
            return by_ext_id, by_username
        _index_users_page(data, by_ext_id, by_username)
        url = _next_users_page_url(data)
    return by_ext_id, by_username


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
    """Return True when a userName match is safe to adopt for the current Authentik user.

    Recovery is allowed when the Apple record has no ``externalId`` (lost linkage) or
    already carries the same ``externalId``.  A *different* ``externalId`` means the
    record belongs to another Authentik user — adopting it would corrupt that account.
    """
    found_ext = str(apple_user.get("externalId") or "").strip()
    current_ext = str(authentik_external_id or "").strip()
    return not found_ext or found_ext == current_ext


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


def _build_update_request(user: dict, mode: str, apple_id: str) -> tuple[str, dict[str, Any], list[str]]:
    """Build the outbound Apple SCIM update request for the configured mode."""
    fields = _update_fields_for_mode(mode)
    if mode == "replace_all":
        # Apple rejects PUT bodies that include `externalId` (immutable
        # after creation) or omit the resource `id` — send everything else
        # from `user` plus the Apple-assigned id, not the raw dict.
        put_body = {k: v for k, v in user.items() if k != "externalId"}
        put_body["id"] = apple_id
        return "PUT", put_body, fields

    operations: list[dict[str, Any]] = []
    for field_name in fields:
        if field_name == "externalId":
            value: Any = str(user.get("externalId") or "").strip()
        elif field_name == "userName":
            value = user.get("userName")
        elif field_name == "name":
            value = user.get("name", {})
        elif field_name == "emails":
            value = user.get("emails", [])
        else:
            value = user.get("active", True)
        operations.append({"op": "Replace", "path": field_name, "value": value})
    return (
        "PATCH",
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": operations,
        },
        fields,
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
    label: str = "",
) -> None:
    """PATCH a user update. Shared by normal update path and 409-recovery path."""
    apple_id = apple_user["id"]
    method, update_body, changed_fields = _build_update_request(new_user, settings.apple_scim_update_mode, apple_id)
    if method == "PUT":
        resp = await client.put(f"{APPLE_SCIM_BASE}/Users/{apple_id}", json=update_body, headers=headers)
    else:
        resp = await client.patch(f"{APPLE_SCIM_BASE}/Users/{apple_id}", json=update_body, headers=headers)
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
    resp = await client.patch(f"{APPLE_SCIM_BASE}/Users/{apple_id}", json=body, headers=headers)
    if resp.status_code in (200, 204):
        result.updated += 1
        apple_user["externalId"] = external_id
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
    scim_filter = quote('"' + username + '"')
    filter_url = f"{APPLE_SCIM_BASE}/Users?filter=userName%20eq%20{scim_filter}"
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
        return resp.json()
    except Exception:
        logger.warning(
            "Apple SCIM: 409-recovery filter query returned non-JSON response=%s",
            response_metadata(resp),
        )
        return None


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
        await _patch_external_id(client, headers, apple_user, user, result)
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
        await _patch_user(client, headers, apple_user, user, result, label=label)
    elif not external_id_patch_attempted:
        # A failed repair attempt is already counted via
        # result.errors (and update_400_invalid_request)
        # inside _patch_external_id — don't also count it
        # here as unchanged, which would double-count the
        # same user into two mutually-exclusive buckets.
        result.unchanged += 1
        if patch_label is None:
            logger.debug("Apple SCIM: unchanged %s", _log_user_ref(user))


async def _handle_409(
    client: httpx.AsyncClient,
    headers: dict,
    user: dict,
    result: SyncResult,
) -> None:
    """Handle 409 on POST using Authentik pattern: query by userName then PATCH.

    409 + scimType=uniqueness → user exists in Apple but wasn't returned in GET list
    (typically USERNAME_CONFLICT_WITH_EXISTING_APPLE_ID — personal Apple ID on same email).
    Try to find the user via filter query and re-establish the link.
    """
    username = user.get("userName", "")
    # Mask the email address per SSF_LOG_PII setting so it does not leak
    # into production logs when privacy mode is active.
    safe_username = mask_email(
        username, log_pii=settings.log_pii, pii_key=settings.pii_pepper or settings.ssf_management_token
    )
    payload = await _query_username_filter(client, headers, username, safe_username)
    resources = payload.get("Resources", []) if isinstance(payload, dict) else []
    if resources:
        found = resources[0]
        ext_id = user.get("externalId")
        # Allow recovery when the matched Apple record has no externalId
        # OR the same externalId as the current user (it is our record,
        # just missing from the initial GET list).
        # Reject only when a *different* externalId is present — that means
        # the record belongs to another Authentik user and overwriting it
        # would corrupt that account.
        if not _can_recover_by_username(found, ext_id):
            logger.warning(
                "Apple SCIM: 409-recovery skipped for %s — matched Apple record"
                " has externalId=%s belonging to a different user",
                safe_username,
                found.get("externalId"),
            )
        else:
            await _reconcile_diffs(
                client, headers, found, user, result, recovered_by_username=True, patch_label="409-recovery"
            )
            return

    # Could not locate user — flag as conflict with actionable message.
    result.conflicts += 1
    result.conflict_usernames.append(username)
    logger.warning(
        "Apple SCIM: ⚠️  %s — USERNAME_CONFLICT: email already used as personal Apple ID"
        " | Action: ABM → Settings → Activity Centre → accept pending invitation",
        safe_username,
    )


def _match_apple_user(user: dict, by_ext_id: dict[str, dict], by_username: dict[str, dict]) -> tuple[dict | None, bool]:
    """Return (apple_user, recovered_by_username) for *user* using the externalId/userName lookup."""
    ext_id = user["externalId"]
    by_ext = by_ext_id.get(ext_id)
    if by_ext is not None:
        return by_ext, False

    username_match = by_username.get(_normalize_identifier(user.get("userName")))
    if username_match and _can_recover_by_username(username_match, ext_id):
        return username_match, True

    if username_match:
        logger.warning(
            "Apple SCIM: email match skipped for %s — Apple record externalId=%s"
            " belongs to a different Authentik user",
            _log_user_ref(user),
            username_match.get("externalId"),
        )
    return None, False


async def _create_user(client: httpx.AsyncClient, headers: dict, user: dict, result: SyncResult) -> None:
    """POST a brand-new user to Apple SCIM, delegating 409s to the userName-recovery path."""
    resp = await client.post(f"{APPLE_SCIM_BASE}/Users", json=user, headers=headers)
    if resp.status_code in (200, 201):
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


def _log_sync_start(scim_users: list[dict], by_ext_id: dict, by_username: dict) -> None:
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
        "Apple SCIM: sync start — apple=%d linked_by_external_id=%d email_recovery=%d authentik=%d update_mode=%s",
        len(by_username),
        len(by_ext_id),
        recovered,
        len(scim_users),
        settings.apple_scim_update_mode,
    )


def _log_sync_summary(result: SyncResult) -> None:
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
            "Apple SCIM: ⚠️  %d account(s) pending user acceptance (personal Apple ID conflict) — go to %s",
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
        by_ext_id, by_username = await _get_existing_users(client, headers)
        _log_sync_start(scim_users, by_ext_id, by_username)

        for user in scim_users:
            ext_id = user["externalId"]
            apple_user, recovered_by_username = _match_apple_user(user, by_ext_id, by_username)

            try:
                if apple_user is None:
                    await _create_user(client, headers, user, result)
                else:
                    await _reconcile_diffs(
                        client, headers, apple_user, user, result, recovered_by_username=recovered_by_username
                    )
            except httpx.HTTPError:
                result.errors += 1
                logger.exception("Apple SCIM: network error for externalId=%s", ext_id)

    _log_sync_summary(result)
    return result
