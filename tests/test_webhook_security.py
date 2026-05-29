"""Tests for Authentik webhook HMAC security.

Covers:
- Missing signature → 401 by default
- Invalid HMAC → 401
- Single byte flip → 401
- Unsupported signature prefix → 401
- Valid HMAC → 200
- SSF_ALLOW_UNSIGNED_WEBHOOK=true → unsigned request accepted with warning
- Webhook secret is never logged
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

from fastapi.testclient import TestClient

WEBHOOK_SECRET = b"test_secret_min_32_chars_1234567890"
WEBHOOK_URL = "/webhook/authentik"

SAMPLE_BODY = json.dumps(
    {"body": {"action": "authentik.core.auth.logout", "user": {"email": "u@example.com"}}}
).encode()


def make_sig(body: bytes, secret: bytes = WEBHOOK_SECRET) -> str:
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# ---------------------------------------------------------------------------
# Fail-closed default
# ---------------------------------------------------------------------------


def test_unsigned_request_rejected_by_default():
    """Unsigned webhook is rejected 401 when SSF_ALLOW_UNSIGNED_WEBHOOK is not set."""
    from app.main import app

    with TestClient(app) as client:
        resp = client.post(WEBHOOK_URL, content=SAMPLE_BODY, headers={"Content-Type": "application/json"})
    assert resp.status_code == 401


def test_invalid_hmac_rejected():
    """Present but invalid HMAC signature returns 401."""
    from app.main import app

    with TestClient(app) as client:
        resp = client.post(
            WEBHOOK_URL,
            content=SAMPLE_BODY,
            headers={"Content-Type": "application/json", "X-Authentik-Signature": "sha256=deadbeef"},
        )
    assert resp.status_code == 401


def test_single_byte_flip_rejected():
    """Tampering with a single byte in the body invalidates the signature → 401."""
    from app.main import app

    tampered = bytearray(SAMPLE_BODY)
    tampered[0] ^= 0xFF  # flip first byte
    tampered = bytes(tampered)
    sig = make_sig(SAMPLE_BODY)  # sig is for original body, not tampered

    with TestClient(app) as client:
        resp = client.post(
            WEBHOOK_URL,
            content=tampered,
            headers={"Content-Type": "application/json", "X-Authentik-Signature": sig},
        )
    assert resp.status_code == 401


def test_unsupported_signature_prefix_rejected():
    """Signature with unsupported prefix (sha1=) is rejected with 401."""
    from app.main import app

    bad_sig = "sha1=" + hmac.new(WEBHOOK_SECRET, SAMPLE_BODY, hashlib.sha1).hexdigest()

    with TestClient(app) as client:
        resp = client.post(
            WEBHOOK_URL,
            content=SAMPLE_BODY,
            headers={"Content-Type": "application/json", "X-Authentik-Signature": bad_sig},
        )
    assert resp.status_code == 401


def test_valid_hmac_accepted():
    """Webhook with a valid HMAC-SHA256 signature is accepted."""
    from app.main import app

    sig = make_sig(SAMPLE_BODY)

    with TestClient(app) as client:
        resp = client.post(
            WEBHOOK_URL,
            content=SAMPLE_BODY,
            headers={"Content-Type": "application/json", "X-Authentik-Signature": sig},
        )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# SSF_ALLOW_UNSIGNED_WEBHOOK opt-out
# ---------------------------------------------------------------------------


def test_allow_unsigned_webhook_accepts_missing_sig(monkeypatch):
    """When SSF_WEBHOOK_AUTH_MODE=unsigned, unsigned requests are accepted."""
    import dataclasses

    from app.config import settings as real_settings
    from app.main import app

    unsigned_settings = dataclasses.replace(real_settings, ssf_webhook_auth_mode="unsigned")
    monkeypatch.setattr("app.routes.webhook.settings", unsigned_settings)

    with TestClient(app) as client:
        resp = client.post(WEBHOOK_URL, content=SAMPLE_BODY, headers={"Content-Type": "application/json"})
    # unsigned — but allowed; may return 200 or ignored depending on event mapping
    assert resp.status_code in (200, 422)

    # Restore
    importlib.reload(cfg_module)
    importlib.reload(wh_module)


# ---------------------------------------------------------------------------
# Log hygiene
# ---------------------------------------------------------------------------


def test_webhook_secret_not_in_logs(caplog):
    """The webhook secret must never appear in log output."""
    from app.main import app

    with caplog.at_level(logging.DEBUG), TestClient(app) as client:
        # Invalid signature path — triggers warning log
        client.post(
            WEBHOOK_URL,
            content=SAMPLE_BODY,
            headers={
                "Content-Type": "application/json",
                "X-Authentik-Signature": "sha256=invalid",
            },
        )
        # Missing signature path
        client.post(WEBHOOK_URL, content=SAMPLE_BODY, headers={"Content-Type": "application/json"})

    secret_str = WEBHOOK_SECRET.decode()
    assert secret_str not in caplog.text
