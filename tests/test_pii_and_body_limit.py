"""Tests for PII masking and webhook body-size enforcement."""

from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.security.pii import mask_email

_PII_KEY = "test-pepper-key"


# ---------------------------------------------------------------------------
# PII masking unit tests
# ---------------------------------------------------------------------------


def test_mask_email_log_pii_true_returns_email():
    assert mask_email("alice@example.com", log_pii=True, pii_key=_PII_KEY) == "alice@example.com"


def test_mask_email_log_pii_false_hides_address():
    result = mask_email("alice@example.com", log_pii=False, pii_key=_PII_KEY)
    assert result.startswith("[pii:")
    assert "alice" not in result
    assert "example" not in result


def test_mask_email_log_pii_false_is_consistent():
    """Same email + same key always produces the same token."""
    a = mask_email("alice@example.com", log_pii=False, pii_key=_PII_KEY)
    b = mask_email("alice@example.com", log_pii=False, pii_key=_PII_KEY)
    assert a == b


def test_mask_email_log_pii_false_different_emails_differ():
    a = mask_email("alice@example.com", log_pii=False, pii_key=_PII_KEY)
    b = mask_email("bob@example.com", log_pii=False, pii_key=_PII_KEY)
    assert a != b


def test_mask_email_different_keys_produce_different_tokens():
    """Different HMAC keys produce different tokens for the same email."""
    a = mask_email("alice@example.com", log_pii=False, pii_key="key-one")
    b = mask_email("alice@example.com", log_pii=False, pii_key="key-two")
    assert a != b


def test_mask_email_none_returns_pii_none():
    assert mask_email(None, log_pii=False, pii_key=_PII_KEY) == "[pii:none]"


def test_mask_email_none_log_pii_true_returns_sentinel():
    result = mask_email(None, log_pii=True, pii_key=_PII_KEY)
    assert result == "[pii:none]"


def test_mask_email_hash_matches_hmac():
    email = "test@example.com"
    key = _PII_KEY
    expected_hex = hmac.new(key.encode(), email.encode(), hashlib.sha256).hexdigest()[:8]
    assert mask_email(email, log_pii=False, pii_key=key) == f"[pii:{expected_hex}]"


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
    """A payload at exactly 64 KiB must be accepted (boundary condition)."""
    target = 64 * 1024
    # Build a body whose JSON encoding is exactly target bytes.
    # The wrapper contributes a fixed overhead; fill the rest with a padding string.
    wrapper = '{"body":{"action":"authentik.core.auth.login_failed","user":{"email":"u@ex.com"},"p":""}}'
    overhead = len(wrapper.encode())
    padding = "X" * (target - overhead)
    payload = {"body": {"action": "authentik.core.auth.login_failed", "user": {"email": "u@ex.com"}, "p": padding}}
    body = json.dumps(payload, separators=(",", ":")).encode()
    # Trim or extend to hit exactly target bytes (account for key/value serialisation differences)
    if len(body) > target:
        # Reduce padding until we're at target
        excess = len(body) - target
        payload["body"]["p"] = "X" * max(0, len(padding) - excess)
        body = json.dumps(payload, separators=(",", ":")).encode()
    assert len(body) <= target, f"Test setup produced body of {len(body)} bytes, expected <= {target}"
    resp = client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert resp.status_code == 200


def test_webhook_content_length_header_triggers_fast_rejection(client: TestClient):
    """A signed request with Content-Length > 64 KiB should be rejected before the body is read."""
    # Send a small body but lie about Content-Length to trigger the header check
    body = b'{"body":{}}'
    headers = {
        **_signed_headers(body),
        "Content-Length": str(64 * 1024 + 1),
    }
    resp = client.post("/webhook/authentik", content=body, headers=headers)
    assert resp.status_code == 413


def test_webhook_malformed_json_rejected(client: TestClient):
    """A signed request with invalid JSON body returns 400."""
    body = b"this is not json"
    resp = client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert resp.status_code == 400
    assert "json" in resp.json()["detail"].lower()


def test_webhook_json_array_rejected(client: TestClient):
    """A signed request with a JSON array (not object) returns 400."""
    body = json.dumps([1, 2, 3]).encode()
    resp = client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert resp.status_code == 400


def test_webhook_invalid_utf8_rejected(client: TestClient):
    """A signed request with invalid UTF-8 bytes returns 400."""
    body = b"\xff\xfe invalid utf-8"
    resp = client.post("/webhook/authentik", content=body, headers=_signed_headers(body))
    assert resp.status_code == 400


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
    assert "[pii:" in combined
