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
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app

VALID_TOKEN = "test_management_token_min_32_chars_1234"
VALID_HEADERS = {"Authorization": f"Bearer {VALID_TOKEN}"}


@pytest.fixture
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


@pytest.mark.enable_rate_limit
def test_failed_management_auth_attempts_are_rate_limited(client: TestClient):
    """Repeated bad management tokens are limited before the stream handler runs."""
    from app.auth import _management_auth_failures
    from app.rate_limit import limiter

    limiter.reset()
    _management_auth_failures.clear()

    for _ in range(10):
        resp = client.post(
            "/ssf/streams",
            json={},
            headers={"Authorization": "Bearer wrong_token_value_that_is_long_enough_1234"},
        )
        assert resp.status_code == 403

    resp = client.post(
        "/ssf/streams",
        json={},
        headers={"Authorization": "Bearer wrong_token_value_that_is_long_enough_1234"},
    )
    assert resp.status_code == 429


def test_concurrent_failed_management_auth_attempts_are_not_lost():
    """Concurrent calls for the same client must not race the shared attempt counter.

    Regression test for require_management_auth briefly being a plain `def`:
    FastAPI dispatches a sync dependency to its worker thread pool, so
    concurrent requests can run _record_management_auth_failure's
    check-then-act sequence on real OS threads at once. The race is on the
    "bucket is empty/expired -> pop and recreate" branch specifically (hit
    by every thread on a brand-new client_key, as here) and is too narrow
    to reproduce via brute-force thread hammering alone — individual dict/
    deque operations execute far faster than a GIL switch interval, so
    threads essentially never get preempted mid-critical-section in
    practice. A `_SlowPopDict.pop()` sleep deterministically widens that
    exact window instead, without touching app.auth's real logic.

    With the bug present (no lock, or a non-async dependency dispatched to
    a thread pool), this reliably observed all N concurrent first-time
    attempts landing in *different* recreated deques and none of them
    ever seeing the shared count exceed the limit — i.e. `blocked == 0`
    instead of the correct `N - LIMIT`.
    """
    import threading
    import time
    from collections import defaultdict, deque
    from types import SimpleNamespace

    import app.auth as auth_module
    from app.rate_limit import limiter

    class _SlowPopDict(defaultdict):
        """Sleeps inside pop() to force concurrent threads to interleave there."""

        def pop(self, *args, **kwargs):
            time.sleep(0.005)
            return super().pop(*args, **kwargs)

    limiter.reset()
    original_failures = auth_module._management_auth_failures
    n_threads = 2 * auth_module._MANAGEMENT_AUTH_FAILURE_LIMIT
    auth_module._management_auth_failures = _SlowPopDict(
        lambda: deque(maxlen=auth_module._MANAGEMENT_AUTH_FAILURE_LIMIT + 1)
    )
    was_enabled = limiter.enabled
    limiter.enabled = True
    try:
        fake_request = SimpleNamespace(client=SimpleNamespace(host="race-test-client"))
        allowed = 0
        blocked = 0
        counts_lock = threading.Lock()
        barrier = threading.Barrier(n_threads)

        def _hammer() -> None:
            nonlocal allowed, blocked
            barrier.wait()
            try:
                auth_module._record_management_auth_failure(fake_request)
            except HTTPException:
                with counts_lock:
                    blocked += 1
            else:
                with counts_lock:
                    allowed += 1

        threads = [threading.Thread(target=_hammer) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        limiter.enabled = was_enabled
        auth_module._management_auth_failures = original_failures

    # Exactly the first LIMIT concurrent attempts should be let through;
    # every attempt past that must be rejected. A lost count under
    # concurrency would shift this split (in the extreme, all N allowed).
    assert allowed == auth_module._MANAGEMENT_AUTH_FAILURE_LIMIT
    assert blocked == n_threads - auth_module._MANAGEMENT_AUTH_FAILURE_LIMIT


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
    assert resp.status_code in {307, 503}


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
