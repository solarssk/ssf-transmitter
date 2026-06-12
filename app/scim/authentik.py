"""Fetch users from Authentik via its REST API.

Requires:
  AUTHENTIK_URL   — base URL of your Authentik instance (e.g. https://idp.example.com)
  AUTHENTIK_TOKEN — API token with read access to users (create in Authentik:
                    Admin → Directory → Tokens → Create, type "API")
  APPLE_SCIM_GROUP_ID — (optional) Authentik group UUID; only members of this
                        group will be synced.  Leave unset to sync all active users.

Return values:
  list[dict]  — SCIM-mapped users (may be empty if there are genuinely no users)
  None        — upstream error (network failure, auth error, etc.)
"""

from __future__ import annotations

import logging

import httpx

from app.config import settings
from app.security.http_logging import response_metadata

logger = logging.getLogger(__name__)


def _map_to_scim(user: dict) -> dict:
    """Convert an Authentik user dict to an Apple SCIM 2.0 User object.

    Field mapping:
      Authentik pk    → externalId   (stable identifier used to match records)
      Authentik email → userName     (Apple uses email as the primary login)
      Authentik name  → name.givenName / name.familyName
      Authentik email → emails[].value
      Authentik is_active → active
    """
    full_name: str = user.get("name") or ""

    # UI-CONFIGURABLE(v1.x): scim.name_split_mode
    # Current: split display name on first space → givenName / familyName.
    # Works for European names; CJK/Arabic names may need a different strategy.
    # Future modes: "space" (default), "attributes" (Authentik first_name/last_name),
    # "full_as_given" (entire name → givenName, empty familyName for CJK).
    parts = full_name.split(" ", 1)
    given_name = parts[0]
    family_name = parts[1] if len(parts) > 1 else ""

    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": str(user["pk"]),
        "userName": (user.get("email") or user.get("username", "")).strip(),
        "name": {
            "givenName": given_name,
            "familyName": family_name,
            "formatted": full_name,
        },
        "emails": [
            {"value": (user.get("email") or "").strip(), "primary": True, "type": "work"}
        ],
        "active": user.get("is_active", True),
    }


async def get_users() -> list[dict] | None:
    """Return all eligible Authentik users mapped to SCIM format.

    If APPLE_SCIM_GROUP_ID is set only members of that group are returned.
    Only internal accounts (type=internal) are included; service accounts are
    excluded regardless of the group filter.

    Returns:
        list[dict]: SCIM-mapped users — may be an empty list if there are none.
        None:       An upstream error occurred (misconfiguration, network, auth).
    """
    if not settings.authentik_url or not settings.authentik_token:
        logger.error("Authentik URL or token not configured")
        return None

    headers = {"Authorization": f"Bearer {settings.authentik_token}"}
    base = settings.authentik_url.rstrip("/")

    group_id = (settings.apple_scim_group_id or "").strip()
    if group_id:
        url = (
            f"{base}/api/v3/core/users/"
            f"?groups_by_pk={group_id}&type=internal&page_size=500"
        )
        logger.info("Apple SCIM: Authentik group filtering enabled group_id=%s", group_id)
    else:
        url = f"{base}/api/v3/core/users/?type=internal&page_size=500"
        logger.info("Apple SCIM: Authentik group filtering disabled — syncing all active users")

    all_users: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            while url:
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    if group_id and resp.status_code == 403:
                        logger.error(
                            "Apple SCIM: configured APPLE_SCIM_GROUP_ID=%s could not be read "
                            "(Authentik status=%s). Verify AUTHENTIK_TOKEN has permission to list users "
                            "filtered by group membership.",
                            group_id,
                            resp.status_code,
                        )
                    else:
                        logger.error(
                            "Authentik API error response=%s",
                            response_metadata(resp),
                        )
                    return None
                try:
                    data = resp.json()
                except Exception:
                    logger.error("Authentik API returned non-JSON response=%s", response_metadata(resp))
                    return None
                all_users.extend(data.get("results", []))
                url = data.get("next")  # pagination — None when last page
    except httpx.HTTPError:
        logger.exception("Failed to fetch users from Authentik")
        return None

    if group_id:
        logger.info("Fetched %d Authentik users from Apple SCIM group %s", len(all_users), group_id)
    else:
        logger.info("Fetched %d active Authentik users", len(all_users))

    mapped = []
    for u in all_users:
        pk = u.get("pk")
        if not pk:
            logger.warning(
                "Apple SCIM: skipping Authentik user with missing pk — cannot map to SCIM externalId"
            )
            continue
        ext_id = str(pk)
        email = (u.get("email") or "").strip()
        name = u.get("name") or ""
        if not email:
            # Log as ERROR — a user without email that was previously synced to Apple
            # will NOT receive an active=false deactivation update because we cannot
            # build a valid SCIM record without a userName. Clear the email in
            # Authentik only after disabling the account so the deactivation syncs first.
            logger.error(
                "Apple SCIM: skipping Authentik user pk=%s (no email) — "
                "cannot provision or deactivate in Apple without a userName; "
                "disable the account before removing the email",
                ext_id,
            )
            continue
        if not name.strip():
            logger.warning(
                "Apple SCIM: Authentik user pk=%s has no display name — givenName will be empty",
                ext_id,
            )
        mapped.append(_map_to_scim(u))
    return mapped
