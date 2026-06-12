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
from urllib.parse import quote

import httpx

from app.security.http_logging import response_metadata
from app.security.pii import mask_email

logger = logging.getLogger(__name__)

APPLE_SCIM_BASE = "https://federation.apple.com/feeds/business/scim"
ABM_ACTIVITY_URL = "https://business.apple.com/main/activity"


@dataclass
class SyncResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    conflicts: int = 0   # users that exist but have a personal Apple ID conflict
    errors: int = 0
    conflict_usernames: list[str] = field(default_factory=list)


async def _get_existing_users(
    client: httpx.AsyncClient, headers: dict
) -> tuple[dict[str, dict], dict[str, dict]]:
    """Return all Apple SCIM users indexed by externalId AND by userName.

    Returns:
        (by_ext_id, by_username) — two dicts for primary and fallback lookup.
        by_username keys are lowercased for case-insensitive matching.
    """
    by_ext_id: dict[str, dict] = {}
    by_username: dict[str, dict] = {}
    url = f"{APPLE_SCIM_BASE}/Users?count=200"
    while url:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Apple SCIM list users failed response=%s", response_metadata(resp))
            return by_ext_id, by_username
        try:
            data = resp.json()
        except Exception:
            logger.error("Apple SCIM list users returned non-JSON response=%s", response_metadata(resp))
            return by_ext_id, by_username
        for u in data.get("Resources", []):
            ext_id = u.get("externalId")
            if ext_id:
                by_ext_id[str(ext_id).strip()] = u
            username = u.get("userName", "")
            if username:
                by_username[_normalize_identifier(username)] = u
        # Apple uses startIndex/itemsPerPage pagination (not cursor/next-link)
        total = data.get("totalResults", 0)
        start = data.get("startIndex", 1)
        per_page = data.get("itemsPerPage") or len(data.get("Resources", []))
        if per_page == 0:
            break  # guard: empty page with totalResults > 0 would loop forever
        if start + per_page - 1 < total:
            url = f"{APPLE_SCIM_BASE}/Users?count=200&startIndex={start + per_page}"
        else:
            url = None
    return by_ext_id, by_username


def _normalize_identifier(value: object) -> str:
    """Normalize a SCIM identifier for stable semantic comparisons."""
    return str(value or "").strip().lower()


def _normalize_email(value: object) -> str:
    """Normalize an email address for comparison without changing payloads sent to Apple."""
    return str(value or "").strip().lower()


def _scim_log_username(username: str | None) -> str:
    """Return a log-safe userName, masked unless SSF_LOG_PII is enabled."""
    from app.config import settings  # late import — avoids circular at module load

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


def _build_patch_body(user: dict) -> dict:
    """Build an RFC 7644 PATCH body for Apple SCIM user updates.

    PATCH keeps ``externalId`` stable while replacing only the attributes this
    service owns, avoiding the repeated update loop caused by full-replace PUT
    responses that omit or drop optional fields.
    """
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "Replace", "path": "externalId", "value": str(user.get("externalId") or "").strip()},
            {"op": "Replace", "path": "userName", "value": user.get("userName")},
            {"op": "Replace", "path": "name", "value": user.get("name", {})},
            {"op": "Replace", "path": "emails", "value": user.get("emails", [])},
            {"op": "Replace", "path": "active", "value": user.get("active", True)},
        ],
    }


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
    update_body = _build_patch_body(new_user)
    resp = await client.patch(f"{APPLE_SCIM_BASE}/Users/{apple_id}", json=update_body, headers=headers)
    if resp.status_code in (200, 204):
        result.updated += 1
        logger.info(
            "Apple SCIM: updated %s%s",
            _log_user_ref(new_user),
            f" ({label})" if label else "",
        )
    else:
        result.errors += 1
        logger.warning(
            "Apple SCIM: update failed externalId=%s appleId=%s response=%s",
            new_user.get("externalId"), apple_id, response_metadata(resp),
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
    logger.warning(
        "Apple SCIM: externalId patch failed externalId=%s appleId=%s response=%s",
        external_id,
        apple_id,
        response_metadata(resp),
    )
    return False


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
    # SCIM RFC 7644 filter literals use double quotes (not single quotes from repr())
    scim_filter = quote('"' + username + '"')
    filter_url = f"{APPLE_SCIM_BASE}/Users?filter=userName%20eq%20{scim_filter}"
    from app.config import settings  # late import — avoids circular at module load
    safe_username = mask_email(username, log_pii=settings.log_pii,
                               pii_key=settings.pii_pepper or settings.ssf_management_token)
    try:
        resp = await client.get(filter_url, headers=headers)
        if resp.status_code == 200:
            try:
                payload = resp.json()
            except Exception:
                logger.warning(
                    "Apple SCIM: 409-recovery filter query returned non-JSON response=%s",
                    response_metadata(resp),
                )
            else:
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
                        found_ext_id = found.get("externalId")
                        logger.warning(
                            "Apple SCIM: 409-recovery skipped for %s — matched Apple record"
                            " has externalId=%s belonging to a different user",
                            safe_username, found_ext_id,
                        )
                    else:
                        diffs = _field_diffs(found, user)
                        external_id_patched = False
                        non_external_diffs = {k: v for k, v in diffs.items() if k != "externalId"}
                        if diffs.get("externalId") and not any(non_external_diffs.values()):
                            external_id_patched = await _patch_external_id(client, headers, found, user, result)
                            diffs = _field_diffs(found, user, include_external_id=False)
                        if any(diffs.values()):
                            await _patch_user(client, headers, found, user, result, label="409-recovery")
                        elif not external_id_patched:
                            result.unchanged += 1
                        return
        else:
            logger.warning("Apple SCIM: 409-recovery filter query failed status=%s userName=%s",
                           resp.status_code, safe_username)
    except httpx.HTTPError:
        logger.warning("Apple SCIM: 409-recovery network error for userName=%s", safe_username)

    # Could not locate user — flag as conflict with actionable message.
    # Mask the email address per SSF_LOG_PII setting so it does not leak
    # into production logs when privacy mode is active.
    result.conflicts += 1
    result.conflict_usernames.append(username)
    from app.config import settings  # late import — avoids circular at module load
    safe_username = mask_email(username, log_pii=settings.log_pii,
                               pii_key=settings.pii_pepper or settings.ssf_management_token)
    logger.warning(
        "Apple SCIM: ⚠️  %s — USERNAME_CONFLICT: email already used as personal Apple ID"
        " | Action: ABM → Settings → Activity Centre → accept pending invitation",
        safe_username,
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

        # Count users that will be recovered via userName fallback — mirrors the
        # sync loop condition exactly: externalId miss AND username match has no
        # externalId of its own (so we won't overwrite an unrelated record).
        recovered = sum(
            1 for u in scim_users
            if not by_ext_id.get(str(u["externalId"]).strip())
            and (m := by_username.get(_normalize_identifier(u.get("userName")))) is not None
            and _can_recover_by_username(m, u["externalId"])
        )
        apple_total = len(by_username)
        logger.info(
            "Apple SCIM: sync start — apple=%d linked_by_external_id=%d"
            " email_recovery=%d authentik=%d",
            apple_total,
            len(by_ext_id),
            recovered,
            len(scim_users),
        )

        for user in scim_users:
            ext_id = user["externalId"]
            username_key = _normalize_identifier(user.get("userName"))
            by_ext = by_ext_id.get(ext_id)
            recovered_by_username = False
            if by_ext is not None:
                apple_user = by_ext
            else:
                username_match = by_username.get(username_key)
                if username_match and _can_recover_by_username(username_match, ext_id):
                    apple_user = username_match
                    recovered_by_username = True
                else:
                    if username_match:
                        logger.warning(
                            "Apple SCIM: email match skipped for %s — Apple record externalId=%s"
                            " belongs to a different Authentik user",
                            _log_user_ref(user),
                            username_match.get("externalId"),
                        )
                    apple_user = None
                    recovered_by_username = False

            try:
                if apple_user is None:
                    resp = await client.post(f"{APPLE_SCIM_BASE}/Users", json=user, headers=headers)
                    if resp.status_code in (200, 201):
                        result.created += 1
                        logger.info("Apple SCIM: created %s", _log_user_ref(user))
                    elif resp.status_code == 409:
                        await _handle_409(client, headers, user, result)
                    else:
                        result.errors += 1
                        logger.warning(
                            "Apple SCIM: create failed externalId=%s response=%s",
                            ext_id, response_metadata(resp),
                        )
                else:
                    diffs = _field_diffs(apple_user, user)
                    external_id_patched = False
                    non_external_diffs = {k: v for k, v in diffs.items() if k != "externalId"}
                    if recovered_by_username and diffs.get("externalId") and not any(non_external_diffs.values()):
                        external_id_patched = await _patch_external_id(client, headers, apple_user, user, result)
                        diffs = _field_diffs(apple_user, user, include_external_id=False)
                    if any(diffs.values()):
                        changed = _format_changed_fields(diffs)
                        logger.debug(
                            "Apple SCIM: update %s — changed: %s",
                            _log_user_ref(user),
                            changed,
                        )
                        await _patch_user(client, headers, apple_user, user, result, label=changed)
                    elif not external_id_patched:
                        result.unchanged += 1
                        logger.debug("Apple SCIM: unchanged %s", _log_user_ref(user))

            except httpx.HTTPError:
                result.errors += 1
                logger.exception("Apple SCIM: network error for externalId=%s", ext_id)

    logger.info(
        "Apple SCIM: sync done — created=%d updated=%d unchanged=%d conflicts=%d errors=%d",
        result.created, result.updated, result.unchanged, result.conflicts, result.errors,
    )
    if result.conflicts > 0:
        logger.warning(
            "Apple SCIM: ⚠️  %d account(s) pending user acceptance (personal Apple ID conflict)"
            " — go to %s",
            result.conflicts, ABM_ACTIVITY_URL,
        )
    return result
