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
    parts = full_name.split(" ", 1)
    given_name = parts[0]
    family_name = parts[1] if len(parts) > 1 else ""

    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": str(user["pk"]),
        "userName": user.get("email") or user.get("username", ""),
        "name": {
            "givenName": given_name,
            "familyName": family_name,
            "formatted": full_name,
        },
        "emails": [
            {"value": user.get("email") or "", "primary": True, "type": "work"}
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

    if settings.apple_scim_group_id:
        url = (
            f"{base}/api/v3/core/users/"
            f"?groups_by_pk={settings.apple_scim_group_id}&type=internal&page_size=500"
        )
    else:
        url = f"{base}/api/v3/core/users/?type=internal&page_size=500"

    all_users: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            while url:
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
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

    logger.info("Fetched %d users from Authentik", len(all_users))

    mapped = []
    for u in all_users:
        email = u.get("email") or ""
        name = u.get("name") or ""
        ext_id = str(u.get("pk", ""))
        if not email:
            logger.warning(
                "Apple SCIM: skipping Authentik user pk=%s (no email) — cannot create Managed Apple Account",
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
