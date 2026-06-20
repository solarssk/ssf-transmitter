"""Tests for HTTP security headers and request correlation IDs."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


@pytest.fixture()
def client():
    with TestClient(app) as tc:
        yield tc


def _assert_security_headers(response) -> None:
    for header, value in SECURITY_HEADERS.items():
        assert response.headers.get(header) == value


def test_jwks_has_security_headers(client: TestClient):
    resp = client.get("/jwks.json")
    assert resp.status_code == 200
    _assert_security_headers(resp)


def test_root_html_has_csp(client: TestClient):
    resp = client.get("/", headers={"Accept": "text/html"})
    assert resp.status_code == 200
    _assert_security_headers(resp)
    assert "Content-Security-Policy" in resp.headers


def test_request_id_generated(client: TestClient):
    resp = client.get("/jwks.json")
    assert resp.headers.get("X-Request-ID")


def test_request_id_honors_incoming_header(client: TestClient):
    resp = client.get("/jwks.json", headers={"X-Request-ID": "abc12345"})
    assert resp.headers.get("X-Request-ID") == "abc12345"


@pytest.mark.enable_rate_limit
def test_rate_limit_response_has_security_headers(client: TestClient):
    """429 responses must include security headers and a correlation ID."""
    from app.rate_limit import limiter

    limiter.reset()
    payload = {
        "aud": "rate-limit-aud",
        "delivery": {"endpoint_url": "https://receiver.example.test/events"},
    }
    for _ in range(10):
        resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
        assert resp.status_code == 201
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 429
    _assert_security_headers(resp)
    assert resp.headers.get("X-Request-ID")


@pytest.mark.enable_rate_limit
def test_patch_stream_by_id_uses_independent_rate_limit(client: TestClient):
    """PATCH /streams/{id} must not consume or check the non-ID PATCH quota."""
    from app.rate_limit import limiter

    limiter.reset()
    create_resp = client.post(
        "/ssf/streams",
        json={
            "aud": "rate-limit-aud",
            "delivery": {"endpoint_url": "https://receiver.example.test/events"},
        },
        headers=MGMT_HEADERS,
    )
    assert create_resp.status_code == 201
    stream_id = create_resp.json()["stream_id"]

    for idx in range(20):
        resp = client.patch(
            "/ssf/streams",
            json={"status": "paused" if idx % 2 else "enabled"},
            headers=MGMT_HEADERS,
        )
        assert resp.status_code == 200

    exhausted = client.patch("/ssf/streams", json={"status": "paused"}, headers=MGMT_HEADERS)
    assert exhausted.status_code == 429

    by_id_resp = client.patch(
        f"/ssf/streams/{stream_id}",
        json={"status": "disabled"},
        headers=MGMT_HEADERS,
    )
    assert by_id_resp.status_code == 200
    assert by_id_resp.json()["status"] == "disabled"
