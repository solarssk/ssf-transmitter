"""Tests that confirm secrets and PII are never written to log records.

These are regression tests — if any refactor causes a secret to leak into
logs, these tests will catch it before it reaches production.

All caplog scopes are restricted to the ``app`` logger namespace so that
third-party library DEBUG output (e.g. aiosqlite SQL statements, httpx
request tracing) does not interfere with the assertions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

import pytest
from fastapi.testclient import TestClient

from app.main import app

MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}
_WEBHOOK_SECRET = b"test_secret_min_32_chars_1234567890"
_RECEIVER_TOKEN = "receiver-secret-token"
_MANAGEMENT_TOKEN = "test_management_token_min_32_chars_1234"


def _signed_headers(body: bytes) -> dict[str, str]:
    sig = hmac.new(_WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return {"Content-Type": "application/json", "X-Authentik-Signature": f"sha256={sig}"}


@pytest.fixture()
def client():
    with TestClient(app) as tc:
        yield tc


def _app_log_text(caplog) -> str:
    """Return formatted text of all log records emitted by the *app* namespace."""
    return " ".join(r.getMessage() for r in caplog.records if r.name.startswith("app."))


# ---------------------------------------------------------------------------
# Management token is never logged
# ---------------------------------------------------------------------------


def test_management_token_not_logged_on_valid_auth(client: TestClient, caplog):
    """A successful management API call must not write the bearer token to app logs."""
    with caplog.at_level(logging.DEBUG, logger="app"):
        client.delete("/ssf/streams", headers=MGMT_HEADERS)
    assert _MANAGEMENT_TOKEN not in _app_log_text(caplog)


def test_management_token_not_logged_on_invalid_auth(client: TestClient, caplog):
    """A rejected management API call must not echo the (wrong) token to app logs."""
    bad_token = "this_is_the_wrong_token_1234567890abcd"
    with caplog.at_level(logging.DEBUG, logger="app"):
        client.get("/ssf/streams", headers={"Authorization": f"Bearer {bad_token}"})
    assert bad_token not in _app_log_text(caplog)


# ---------------------------------------------------------------------------
# Receiver token is never logged
# ---------------------------------------------------------------------------


def test_receiver_token_not_logged_on_stream_create(client: TestClient, caplog):
    """Creating a stream must not write the receiver endpoint token to app logs."""
    with caplog.at_level(logging.DEBUG, logger="app"):
        client.post(
            "/ssf/streams",
            json={
                "aud": "test-aud",
                "delivery": {
                    "endpoint_url": "https://receiver.example.test/events",
                    "endpoint_url_token": _RECEIVER_TOKEN,
                },
            },
            headers=MGMT_HEADERS,
        )
    assert _RECEIVER_TOKEN not in _app_log_text(caplog)


def test_receiver_token_not_in_stream_response(client: TestClient):
    """GET /ssf/streams must not return the receiver token in the response body."""
    client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://receiver.example.test/events",
                "endpoint_url_token": _RECEIVER_TOKEN,
            },
        },
        headers=MGMT_HEADERS,
    )
    resp = client.get("/ssf/streams", headers=MGMT_HEADERS)
    assert resp.status_code == 200
    assert _RECEIVER_TOKEN not in json.dumps(resp.json())


def test_receiver_token_not_in_create_response(client: TestClient):
    """POST /ssf/streams response must not include the receiver token."""
    resp = client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://receiver.example.test/events",
                "endpoint_url_token": _RECEIVER_TOKEN,
            },
        },
        headers=MGMT_HEADERS,
    )
    assert resp.status_code == 201
    assert _RECEIVER_TOKEN not in json.dumps(resp.json())


# ---------------------------------------------------------------------------
# Webhook HMAC secret is never logged
# ---------------------------------------------------------------------------


def test_webhook_secret_not_logged_on_valid_request(client: TestClient, caplog):
    """Processing a valid signed webhook must not write the HMAC secret to app logs."""
    body = json.dumps({"body": {"action": "authentik.core.auth.logout", "user": {"email": "u@example.com"}}}).encode()
    with caplog.at_level(logging.DEBUG, logger="app"):
        client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert _WEBHOOK_SECRET.decode() not in _app_log_text(caplog)


def test_webhook_secret_not_logged_on_invalid_hmac(client: TestClient, caplog):
    """Rejecting a webhook with bad HMAC must not log the expected vs provided values."""
    body = b'{"body": {}}'
    with caplog.at_level(logging.DEBUG, logger="app"):
        client.post(
            "/webhook/authentik",
            content=body,
            headers={"X-Authentik-Signature": "sha256=badhash", "Content-Type": "application/json"},
        )
    assert _WEBHOOK_SECRET.decode() not in _app_log_text(caplog)


# Note: the "email never appears in logs" regression test lives in
# tests/test_pii_and_body_limit.py (PR: PII masking + webhook body limit),
# which adds SSF_LOG_PII support and the mask_email() call to webhook.py.
# It is not included here because the feature is not yet on main.


# ---------------------------------------------------------------------------
# Upstream response bodies are never logged
# ---------------------------------------------------------------------------


def test_response_metadata_excludes_raw_body_secrets():
    """HTTP failure metadata must include diagnostics without raw body content."""
    import httpx

    from app.security.http_logging import response_metadata

    raw_secret = "upstream-refresh-token-secret"
    resp = httpx.Response(401, json={"error": "invalid_client", "refresh_token": raw_secret})

    metadata = response_metadata(resp)

    assert raw_secret not in repr(metadata)
    assert metadata["status_code"] == 401
    assert metadata["body_len"] == len(resp.content)
    assert metadata["body_sha256_8"]


@pytest.mark.anyio
async def test_apple_token_refresh_failure_does_not_log_response_body(monkeypatch, caplog):
    """Apple token refresh errors must not log raw OAuth response bodies."""
    import httpx

    from app.scim import token as token_module

    raw_client_secret = "expired-client-secret-from-upstream"
    raw_refresh_token = "stored-refresh-token-secret"

    class FakeAsyncClient:
        def __init__(self, timeout: float):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, data):
            return httpx.Response(
                401,
                json={
                    "error": "invalid_client",
                    "client_secret": raw_client_secret,
                    "refresh_token": raw_refresh_token,
                },
            )

    async def fake_send_alert(*args, **kwargs):
        return None

    monkeypatch.setattr(token_module.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(token_module, "send_alert", fake_send_alert)

    with caplog.at_level(logging.ERROR, logger="app"):
        result = await token_module._refresh(raw_refresh_token)

    assert result is None
    log_text = _app_log_text(caplog)
    assert raw_client_secret not in log_text
    assert raw_refresh_token not in log_text
    assert "body_sha256_8" in log_text
