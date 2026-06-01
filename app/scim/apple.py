"""Apple SCIM 2.0 client.

Pushes users from Authentik to Apple Business Manager via Apple's SCIM endpoint.
Uses externalId (Authentik PK) to correlate records across systems so that
renames / email changes are handled as updates rather than create+delete.

Apple SCIM base URL: https://federation.apple.com/feeds/business/scim
Note: Apple's SCIM endpoint does not include /v2 in the public URL.

Sync strategy (Authentik pattern):
1. GET all existing Apple users → index by externalId (primary) and userName (fallback)
2. For each Authentik user:
   - Found by externalId or userName, unchanged → skip
   - Found by externalId or userName, changed  → PUT (full update, keeps externalId)
   - Not found → POST; on 409 → query by userName filter then PUT
3. Users in Apple absent from Authentik are left untouched (deactivate in Authentik first)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

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
            logger.error("Apple SCIM list users failed status=%s body=%r", resp.status_code, resp.text[:300])
            return by_ext_id, by_username
        try:
            data = resp.json()
        except Exception:
            logger.error("Apple SCIM list users returned non-JSON body=%r", resp.text[:300])
            return by_ext_id, by_username
        for u in data.get("Resources", []):
            ext_id = u.get("externalId")
            if ext_id:
                by_ext_id[ext_id] = u
            username = u.get("userName", "")
            if username:
                by_username[username.lower()] = u
        # Apple uses startIndex/itemsPerPage pagination (not cursor/next-link)
        total = data.get("totalResults", 0)
        start = data.get("startIndex", 1)
        per_page = data.get("itemsPerPage", len(data.get("Resources", [])))
        if start + per_page - 1 < total:
            url = f"{APPLE_SCIM_BASE}/Users?count=200&startIndex={start + per_page}"
        else:
            url = None
    return by_ext_id, by_username


def _users_differ(existing: dict, new: dict) -> bool:
    """Return True if any syncable field has changed.

    Apple may omit `active` from GET responses when the value is True —
    treat a missing field as True so we don't spuriously update every user.
    """
    checks = [
        existing.get("userName") != new.get("userName"),
        existing.get("name", {}).get("givenName") != new.get("name", {}).get("givenName"),
        existing.get("name", {}).get("familyName") != new.get("name", {}).get("familyName"),
        existing.get("active", True) != new.get("active", True),
    ]
    existing_email = next((e["value"] for e in existing.get("emails", []) if e.get("primary")), None)
    new_email = next((e["value"] for e in new.get("emails", []) if e.get("primary")), None)
    checks.append(existing_email != new_email)
    return any(checks)


def _build_put_body(user: dict, apple_id: str) -> dict:
    """Build a PUT body: strip externalId (Apple rejects it on updates), add Apple's id."""
    body = {k: v for k, v in user.items() if k != "externalId"}
    body["id"] = apple_id
    return body


async def _put_user(
    client: httpx.AsyncClient,
    headers: dict,
    apple_user: dict,
    new_user: dict,
    result: SyncResult,
    *,
    label: str = "",
) -> None:
    """PUT a user update. Shared by normal update path and 409-recovery path."""
    apple_id = apple_user["id"]
    update_body = _build_put_body(new_user, apple_id)
    resp = await client.put(f"{APPLE_SCIM_BASE}/Users/{apple_id}", json=update_body, headers=headers)
    if resp.status_code in (200, 204):
        result.updated += 1
        logger.debug(
            "Apple SCIM: updated user%s externalId=%s userName=%s",
            f" ({label})" if label else "",
            new_user.get("externalId"),
            new_user.get("userName"),
        )
    else:
        result.errors += 1
        logger.warning(
            "Apple SCIM: update failed externalId=%s appleId=%s status=%s body=%r",
            new_user.get("externalId"), apple_id, resp.status_code, resp.text[:300],
        )


async def _handle_409(
    client: httpx.AsyncClient,
    headers: dict,
    user: dict,
    result: SyncResult,
) -> None:
    """Handle 409 on POST using Authentik pattern: query by userName then PUT.

    409 + scimType=uniqueness → user exists in Apple but wasn't returned in GET list
    (typically USERNAME_CONFLICT_WITH_EXISTING_APPLE_ID — personal Apple ID on same email).
    Try to find the user via filter query and re-establish the link.
    """
    username = user.get("userName", "")
    # SCIM RFC 7644 filter literals use double quotes (not single quotes from repr())
    scim_filter = quote('"' + username + '"')
    filter_url = f"{APPLE_SCIM_BASE}/Users?filter=userName%20eq%20{scim_filter}"
    try:
        resp = await client.get(filter_url, headers=headers)
        if resp.status_code == 200:
            resources = resp.json().get("Resources", [])
            if resources:
                await _put_user(client, headers, resources[0], user, result, label="409-recovery")
                return
        else:
            logger.warning("Apple SCIM: 409-recovery filter query failed status=%s userName=%s",
                           resp.status_code, username)
    except httpx.HTTPError:
        logger.warning("Apple SCIM: 409-recovery network error for userName=%s", username)

    # Could not locate user — flag as conflict with actionable message
    result.conflicts += 1
    result.conflict_usernames.append(username)
    logger.warning(
        "Apple SCIM: ⚠️  %s — USERNAME_CONFLICT: email already used as personal Apple ID"
        " | Action: ABM → Settings → Activity Centre → accept pending invitation",
        username,
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

        recovered = sum(1 for u in scim_users if
                        not by_ext_id.get(u["externalId"])
                        and by_username.get(u.get("userName", "").lower()))
        logger.info(
            "Apple SCIM: found %d existing users (%d by externalId, %d recovered by userName),"
            " syncing %d from Authentik",
            len(by_ext_id) + len({k for k in by_username if k not in
                                   {v.get("userName", "").lower() for v in by_ext_id.values()}}),
            len(by_ext_id),
            recovered,
            len(scim_users),
        )

        for user in scim_users:
            ext_id = user["externalId"]
            username_key = user.get("userName", "").lower()
            by_ext = by_ext_id.get(ext_id)
            apple_user = by_ext or by_username.get(username_key)
            # If found only via userName fallback the externalId linkage is broken —
            # always PUT even when fields are unchanged so future email changes
            # can still be tracked (we won't lose the user on the next sync).
            needs_relink = apple_user is not None and by_ext is None

            try:
                if apple_user is None:
                    resp = await client.post(f"{APPLE_SCIM_BASE}/Users", json=user, headers=headers)
                    if resp.status_code in (200, 201):
                        result.created += 1
                        logger.debug("Apple SCIM: created user externalId=%s userName=%s",
                                     ext_id, user.get("userName"))
                    elif resp.status_code == 409:
                        await _handle_409(client, headers, user, result)
                    else:
                        result.errors += 1
                        logger.warning(
                            "Apple SCIM: create failed externalId=%s status=%s body=%r",
                            ext_id, resp.status_code, resp.text[:300],
                        )
                elif needs_relink or _users_differ(apple_user, user):
                    label = "relink" if needs_relink and not _users_differ(apple_user, user) else ""
                    await _put_user(client, headers, apple_user, user, result, label=label)
                else:
                    result.unchanged += 1

            except httpx.HTTPError:
                result.errors += 1
                logger.exception("Apple SCIM: network error for externalId=%s", ext_id)

    logger.info(
        "Apple SCIM sync complete created=%d updated=%d unchanged=%d conflicts=%d errors=%d",
        result.created, result.updated, result.unchanged, result.conflicts, result.errors,
    )
    if result.conflicts > 0:
        logger.warning(
            "Apple SCIM: ⚠️  %d account(s) pending user acceptance (personal Apple ID conflict)"
            " — go to %s",
            result.conflicts, ABM_ACTIVITY_URL,
        )
    return result
