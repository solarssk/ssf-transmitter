"""Apple SCIM 2.0 client.

Pushes users from Authentik to Apple Business Manager via Apple's SCIM endpoint.
Uses externalId (Authentik PK) to correlate records across systems so that
renames / email changes are handled as updates rather than create+delete.

Apple SCIM base URL: https://federation.apple.com/feeds/business/scim
Note: Apple's SCIM endpoint does not include /v2 in the public URL.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

APPLE_SCIM_BASE = "https://federation.apple.com/feeds/business/scim"


@dataclass
class SyncResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    errors: int = 0


async def _get_existing_users(client: httpx.AsyncClient, headers: dict) -> dict[str, dict]:
    """Return all Apple SCIM users keyed by externalId."""
    users: dict[str, dict] = {}
    url = f"{APPLE_SCIM_BASE}/Users?count=200"
    while url:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Apple SCIM list users failed status=%s body=%r", resp.status_code, resp.text[:300])
            return users
        try:
            data = resp.json()
        except Exception:
            logger.error("Apple SCIM list users returned non-JSON body=%r", resp.text[:300])
            return users
        for u in data.get("Resources", []):
            ext_id = u.get("externalId")
            if ext_id:
                users[ext_id] = u
        # Apple uses startIndex/itemsPerPage pagination (not cursor/next-link)
        total = data.get("totalResults", 0)
        start = data.get("startIndex", 1)
        per_page = data.get("itemsPerPage", len(data.get("Resources", [])))
        if start + per_page - 1 < total:
            url = f"{APPLE_SCIM_BASE}/Users?count=200&startIndex={start + per_page}"
        else:
            url = None
    return users


def _users_differ(existing: dict, new: dict) -> bool:
    """Return True if any syncable field has changed."""
    checks = [
        existing.get("userName") != new.get("userName"),
        existing.get("name", {}).get("givenName") != new.get("name", {}).get("givenName"),
        existing.get("name", {}).get("familyName") != new.get("name", {}).get("familyName"),
        existing.get("active") != new.get("active"),
    ]
    existing_email = next((e["value"] for e in existing.get("emails", []) if e.get("primary")), None)
    new_email = next((e["value"] for e in new.get("emails", []) if e.get("primary")), None)
    checks.append(existing_email != new_email)
    return any(checks)


async def sync_users(access_token: str, scim_users: list[dict]) -> SyncResult:
    """Upsert Authentik users into Apple Business Manager.

    Strategy:
    1. Fetch all existing Apple users (keyed by externalId = Authentik PK)
    2. For each Authentik user:
       - If found in Apple and unchanged → skip
       - If found in Apple and changed   → PUT (full update)
       - If not found                    → POST (create)
    Users present in Apple but absent from Authentik are left untouched — the
    admin should deactivate them in Authentik first (active=false), which will
    propagate on the next sync.
    """
    result = SyncResult()
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/scim+json",
        "Accept": "application/scim+json",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        existing = await _get_existing_users(client, headers)
        logger.info("Apple SCIM: found %d existing users, syncing %d from Authentik", len(existing), len(scim_users))

        for user in scim_users:
            ext_id = user["externalId"]
            apple_user = existing.get(ext_id)

            try:
                if apple_user is None:
                    # Create new user
                    resp = await client.post(f"{APPLE_SCIM_BASE}/Users", json=user, headers=headers)
                    if resp.status_code in (200, 201):
                        result.created += 1
                        logger.debug("Apple SCIM: created user externalId=%s userName=%s", ext_id, user.get("userName"))
                    else:
                        result.errors += 1
                        logger.warning(
                            "Apple SCIM: create failed externalId=%s status=%s body=%r",
                            ext_id, resp.status_code, resp.text[:300],
                        )
                elif _users_differ(apple_user, user):
                    # Update existing user (full PUT)
                    apple_id = apple_user["id"]
                    resp = await client.put(f"{APPLE_SCIM_BASE}/Users/{apple_id}", json=user, headers=headers)
                    if resp.status_code in (200, 204):
                        result.updated += 1
                        logger.debug("Apple SCIM: updated user externalId=%s userName=%s", ext_id, user.get("userName"))
                    else:
                        result.errors += 1
                        logger.warning(
                            "Apple SCIM: update failed externalId=%s appleId=%s status=%s body=%r",
                            ext_id, apple_id, resp.status_code, resp.text[:300],
                        )
                else:
                    result.unchanged += 1

            except httpx.HTTPError:
                result.errors += 1
                logger.exception("Apple SCIM: network error for externalId=%s", ext_id)

    logger.info(
        "Apple SCIM sync complete created=%d updated=%d unchanged=%d errors=%d",
        result.created, result.updated, result.unchanged, result.errors,
    )
    return result
