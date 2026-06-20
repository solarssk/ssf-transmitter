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
