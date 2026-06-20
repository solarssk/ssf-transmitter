"""Tests for management API bearer token authentication.

Covers:
- Missing Authorization header → 401
- Malformed header (no Bearer prefix) → 401
- Valid header, wrong token → 403
- Valid header, correct token → request proceeds
- Public endpoints remain accessible without auth
- Management token is never logged
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

VALID_TOKEN = "test_management_token_min_32_chars_1234"
VALID_HEADERS = {"Authorization": f"Bearer {VALID_TOKEN}"}


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Rejection cases
# ---------------------------------------------------------------------------


def test_no_auth_header_returns_401(client: TestClient):
    """POST /ssf/streams without Authorization header returns 401."""
    resp = client.post("/ssf/streams", json={})
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_malformed_auth_header_returns_401(client: TestClient):
    """Authorization header without 'Bearer ' prefix is rejected with 401."""
    resp = client.post("/ssf/streams", json={}, headers={"Authorization": VALID_TOKEN})
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_wrong_token_returns_403(client: TestClient):
    """Valid header format but wrong token value returns 403."""
    resp = client.post(
        "/ssf/streams",
        json={},
        headers={"Authorization": "Bearer wrong_token_value_that_is_long_enough_1234"},
    )
    assert resp.status_code == 403


def test_get_streams_requires_auth(client: TestClient):
    """GET /ssf/streams without token returns 401."""
    assert client.get("/ssf/streams").status_code == 401


def test_patch_streams_requires_auth(client: TestClient):
    """PATCH /ssf/streams without token returns 401."""
    assert client.patch("/ssf/streams", json={}).status_code == 401


def test_delete_streams_requires_auth(client: TestClient):
    """DELETE /ssf/streams without token returns 401."""
    assert client.delete("/ssf/streams").status_code == 401


def test_subjects_add_requires_auth(client: TestClient):
    """POST /ssf/streams/subjects:add without token returns 401."""
    assert client.post("/ssf/streams/subjects:add", json={}).status_code == 401


def test_subjects_remove_requires_auth(client: TestClient):
    """POST /ssf/streams/subjects:remove without token returns 401."""
    assert client.post("/ssf/streams/subjects:remove", json={}).status_code == 401


def test_status_requires_auth(client: TestClient):
    """GET /ssf/status without token returns 401."""
    assert client.get("/ssf/status").status_code == 401


def test_apple_scim_status_requires_auth(client: TestClient):
    """GET /apple-scim/status without token returns 401."""
    assert client.get("/apple-scim/status").status_code == 401


def test_apple_scim_status_with_valid_token(client: TestClient):
    """GET /apple-scim/status with valid management token passes auth."""
    resp = client.get("/apple-scim/status", headers=VALID_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_apple_scim_authorize_remains_public(client: TestClient):
    """GET /apple-scim/authorize is reachable without management token (503 when not configured)."""
    resp = client.get("/apple-scim/authorize", follow_redirects=False)
    assert resp.status_code != 401
    assert resp.status_code != 403


# ---------------------------------------------------------------------------
# Public endpoints remain accessible without auth
# ---------------------------------------------------------------------------


def test_wellknown_is_public(client: TestClient):
    """/.well-known/ssf-configuration is accessible without auth."""
    resp = client.get("/.well-known/ssf-configuration")
    assert resp.status_code == 200


def test_jwks_is_public(client: TestClient):
    """/jwks.json is accessible without auth."""
    resp = client.get("/jwks.json")
    assert resp.status_code == 200


def test_webhook_does_not_require_management_token(client: TestClient):
    """POST /webhook/authentik uses HMAC auth, not the management token."""
    # Unsigned request is handled separately (accepted or rejected based on
    # SSF_ALLOW_UNSIGNED_WEBHOOK setting — currently accepted as per current behaviour).
    # The point here is that the management token is NOT checked.
    resp = client.post(
        "/webhook/authentik",
        json={"body": {"action": "some.action"}},
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )
    # Should not be rejected by management auth (may return 200 or 401 for missing HMAC)
    assert resp.status_code != 403


# ---------------------------------------------------------------------------
# Authorized access passes through to actual handler
# ---------------------------------------------------------------------------


def test_valid_token_reaches_handler(client: TestClient):
    """GET /ssf/status with valid token passes auth and reaches the actual handler."""
    # Ensure no stream left over from other tests
    client.delete("/ssf/streams", headers=VALID_HEADERS)
    resp = client.get("/ssf/status", headers=VALID_HEADERS)
    # 200 even with no stream — auth passed, handler returned its normal response
    assert resp.status_code == 200
    assert resp.json()["status"] == "disabled"


def test_management_token_not_in_logs(client: TestClient, caplog):
    """Management token value must never appear in log output."""
    import logging

    with caplog.at_level(logging.DEBUG):
        client.get("/ssf/status")  # no auth — triggers warning log
        client.get("/ssf/status", headers={"Authorization": "Bearer wrong_token_that_is_long_enough_1234"})

    assert VALID_TOKEN not in caplog.text
    assert "wrong_token_that_is_long_enough_1234" not in caplog.text
