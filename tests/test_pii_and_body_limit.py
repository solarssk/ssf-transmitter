"""Tests for PII masking and webhook body-size enforcement."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.pii import mask_email


# ---------------------------------------------------------------------------
# PII masking unit tests
# ---------------------------------------------------------------------------


def test_mask_email_log_pii_true_returns_email():
    assert mask_email("alice@example.com", log_pii=True) == "alice@example.com"


def test_mask_email_log_pii_false_hides_address():
    result = mask_email("alice@example.com", log_pii=False)
    assert result.startswith("[pii:")
    assert "alice" not in result
    assert "example" not in result


def test_mask_email_log_pii_false_is_consistent():
    """Same email always produces the same hash token."""
    a = mask_email("alice@example.com", log_pii=False)
    b = mask_email("alice@example.com", log_pii=False)
    assert a == b


def test_mask_email_log_pii_false_different_emails_differ():
    a = mask_email("alice@example.com", log_pii=False)
    b = mask_email("bob@example.com", log_pii=False)
    assert a != b


def test_mask_email_none_returns_pii_none():
    assert mask_email(None, log_pii=False) == "[pii:none]"


def test_mask_email_none_log_pii_true_returns_sentinel():
    # Even with PII logging on, None should not blow up
    result = mask_email(None, log_pii=True)
    assert result == "[pii:none]"


def test_mask_email_hash_matches_sha256():
    email = "test@example.com"
    expected_hex = hashlib.sha256(email.encode()).hexdigest()[:8]
    assert mask_email(email, log_pii=False) == f"[pii:{expected_hex}]"


# ---------------------------------------------------------------------------
# Webhook body-size limit
# ---------------------------------------------------------------------------


def _signed_headers(body: bytes) -> dict[str, str]:
    sig = hmac.new(b"test_secret_min_32_chars_1234567890", body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Authentik-Signature": f"sha256={sig}",
    }


@pytest.fixture()
def client():
    with TestClient(app) as tc:
        yield tc


def test_webhook_body_within_limit_accepted(client: TestClient):
    body = json.dumps(
        {"body": {"action": "authentik.core.auth.login_failed", "user": {"email": "u@example.com"}}}
    ).encode()
    assert len(body) < 64 * 1024  # sanity
    resp = client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert resp.status_code == 200


def test_webhook_body_over_64kb_rejected(client: TestClient):
    """A payload just over 64 KiB must be rejected with 413."""
    oversized = json.dumps({"body": {"action": "x", "padding": "A" * (64 * 1024)}}).encode()
    resp = client.post("/webhook/authentik", content=oversized, headers=_signed_headers(oversized))
    assert resp.status_code == 413


def test_webhook_exactly_64kb_accepted(client: TestClient):
    """A payload at exactly the limit should be accepted (boundary condition)."""
    # Build a body that is exactly 64 * 1024 bytes
    base = json.dumps({"body": {"action": "authentik.core.auth.login_failed", "user": {"email": "u@ex.com"}, "p": ""}})
    # Pad 'p' so total encoded length == _MAX_BODY_BYTES
    target = 64 * 1024
    current = len(base.encode())
    padding = "X" * max(0, target - current - len('"p": ""') + len('"p": "' + "" + '"'))
    payload = {"body": {"action": "authentik.core.auth.login_failed", "user": {"email": "u@ex.com"}, "p": padding}}
    body = json.dumps(payload).encode()
    # Adjust if slightly off due to JSON serialisation variation
    assert len(body) <= target, f"Test setup error: body is {len(body)} > {target}"
    resp = client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert resp.status_code == 200


def test_webhook_malformed_json_rejected(client: TestClient):
    """A signed request with invalid JSON body returns 400."""
    body = b"this is not json"
    resp = client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert resp.status_code == 400
    assert "json" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# PII in logs — integration: verify email is masked in log output
# ---------------------------------------------------------------------------


def test_email_not_in_logs_by_default(client: TestClient, caplog):
    """With default SSF_LOG_PII=false, email must not appear in log records."""
    import logging

    body = json.dumps(
        {"body": {"action": "authentik.core.auth.logout", "user": {"email": "secret@example.com"}}}
    ).encode()
    with caplog.at_level(logging.INFO, logger="app.routes.webhook"):
        client.post("/webhook/authentik", content=body, headers=_signed_headers(body))

    combined = " ".join(r.message for r in caplog.records)
    assert "secret@example.com" not in combined, "Email leaked into logs despite SSF_LOG_PII=false"
    # The pseudonymous hash should be present instead
    assert "[pii:" in combined
