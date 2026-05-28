"""Tests that confirm secrets and PII are never written to log records.

These are regression tests — if any refactor causes a secret to leak into
logs, these tests will catch it before it reaches production.
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


def _all_log_text(records: list[logging.LogRecord]) -> str:
    return " ".join(r.getMessage() for r in records)


# ---------------------------------------------------------------------------
# Management token is never logged
# ---------------------------------------------------------------------------


def test_management_token_not_logged_on_valid_auth(client: TestClient, caplog):
    """A successful management API call must not write the bearer token to logs."""
    with caplog.at_level(logging.DEBUG):
        client.delete("/ssf/streams", headers=MGMT_HEADERS)
    assert _MANAGEMENT_TOKEN not in _all_log_text(caplog.records)


def test_management_token_not_logged_on_invalid_auth(client: TestClient, caplog):
    """A rejected management API call must not echo the (wrong) token to logs."""
    bad_token = "this_is_the_wrong_token_1234567890abcd"
    with caplog.at_level(logging.DEBUG):
        client.get("/ssf/streams", headers={"Authorization": f"Bearer {bad_token}"})
    assert bad_token not in _all_log_text(caplog.records)


# ---------------------------------------------------------------------------
# Receiver token is never logged
# ---------------------------------------------------------------------------


def test_receiver_token_not_logged_on_stream_create(client: TestClient, caplog):
    """Creating a stream must not write the receiver endpoint token to logs."""
    with caplog.at_level(logging.DEBUG):
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
    assert _RECEIVER_TOKEN not in _all_log_text(caplog.records)


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
    """Processing a valid signed webhook must not write the HMAC secret to logs."""
    body = json.dumps(
        {"body": {"action": "authentik.core.auth.logout", "user": {"email": "u@example.com"}}}
    ).encode()
    with caplog.at_level(logging.DEBUG):
        client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert _WEBHOOK_SECRET.decode() not in _all_log_text(caplog.records)


def test_webhook_secret_not_logged_on_invalid_hmac(client: TestClient, caplog):
    """Rejecting a webhook with bad HMAC must not log the expected vs provided values."""
    body = b'{"body": {}}'
    with caplog.at_level(logging.DEBUG):
        client.post(
            "/webhook/authentik",
            content=body,
            headers={"X-Authentik-Signature": "sha256=badhash", "Content-Type": "application/json"},
        )
    assert _WEBHOOK_SECRET.decode() not in _all_log_text(caplog.records)


# ---------------------------------------------------------------------------
# Email is masked in logs by default
# ---------------------------------------------------------------------------


def test_user_email_not_logged_in_webhook_processing(client: TestClient, caplog):
    """Email addresses must not appear in log records when SSF_LOG_PII=false (default)."""
    target_email = "sensitiveuser@example.com"
    body = json.dumps(
        {"body": {"action": "authentik.core.auth.logout", "user": {"email": target_email}}}
    ).encode()
    with caplog.at_level(logging.INFO, logger="app.routes.webhook"):
        client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert target_email not in _all_log_text(caplog.records)
