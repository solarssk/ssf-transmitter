"""Tests for webhook authentication modes: bearer, hmac, unsigned.

Settings is a frozen dataclass, so per-test overrides use
``dataclasses.replace()`` combined with ``monkeypatch.setattr`` on the
module-level ``settings`` object in ``app.routes.webhook``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import logging

import pytest
from fastapi.testclient import TestClient

from app.config import settings as real_settings
from app.main import app

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}
_WEBHOOK_TOKEN = "test_webhook_token_min_32_chars_1234567"
_WEBHOOK_SECRET = b"test_secret_min_32_chars_1234567890"

_LOGOUT_BODY = json.dumps(
    {"body": {"action": "authentik.core.auth.login_failed", "user": {"email": "u@example.com"}}}
).encode()


def _bearer_headers(token: str = _WEBHOOK_TOKEN) -> dict[str, str]:
    return {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}


def _hmac_headers(body: bytes) -> dict[str, str]:
    sig = hmac.new(_WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return {"Content-Type": "application/json", "X-Authentik-Signature": f"sha256={sig}"}


def _bearer_settings(**overrides):
    """Return a Settings copy with auth_mode=bearer and optional field overrides."""
    return dataclasses.replace(
        real_settings,
        ssf_webhook_auth_mode="bearer",
        ssf_webhook_token=_WEBHOOK_TOKEN,
        **overrides,
    )


def _hmac_settings(**overrides):
    """Return a Settings copy with auth_mode=hmac."""
    return dataclasses.replace(
        real_settings,
        ssf_webhook_auth_mode="hmac",
        ssf_webhook_secret=_WEBHOOK_SECRET.decode(),
        **overrides,
    )


def _unsigned_settings(**overrides):
    """Return a Settings copy with auth_mode=unsigned."""
    return dataclasses.replace(real_settings, ssf_webhook_auth_mode="unsigned", **overrides)


@pytest.fixture()
def client():
    with TestClient(app) as tc:
        yield tc


# ---------------------------------------------------------------------------
# Bearer mode
# ---------------------------------------------------------------------------


def test_bearer_valid_token_accepted(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post("/webhook/authentik", content=_LOGOUT_BODY, headers=_bearer_headers())
    assert resp.status_code == 200


def test_bearer_missing_authorization_rejected(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_bearer_wrong_token_rejected(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers=_bearer_headers(token="wrong_token_that_is_definitely_not_right_abc"),
    )
    assert resp.status_code == 401


def test_bearer_wrong_scheme_rejected(client: TestClient, monkeypatch):
    """Basic auth or other schemes are not accepted in bearer mode."""
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {_WEBHOOK_TOKEN}"},
    )
    assert resp.status_code == 401


def test_bearer_empty_token_rejected(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json", "Authorization": "Bearer "},
    )
    assert resp.status_code == 401


def test_bearer_hmac_signature_not_accepted(client: TestClient, monkeypatch):
    """HMAC signature header does nothing in bearer mode — still needs bearer token."""
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers=_hmac_headers(_LOGOUT_BODY),
    )
    assert resp.status_code == 401


def test_bearer_token_never_in_logs(client: TestClient, monkeypatch, caplog):
    """The bearer token must never appear in any log record."""
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    with caplog.at_level(logging.DEBUG, logger="app"):
        client.post("/webhook/authentik", content=_LOGOUT_BODY, headers=_bearer_headers())
    combined = " ".join(r.getMessage() for r in caplog.records if r.name.startswith("app."))
    assert _WEBHOOK_TOKEN not in combined


# ---------------------------------------------------------------------------
# HMAC mode
# ---------------------------------------------------------------------------


def test_hmac_valid_signature_accepted(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _hmac_settings())
    resp = client.post("/webhook/authentik", content=_LOGOUT_BODY, headers=_hmac_headers(_LOGOUT_BODY))
    assert resp.status_code == 200


def test_hmac_missing_signature_rejected(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _hmac_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_hmac_invalid_signature_rejected(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _hmac_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json", "X-Authentik-Signature": "sha256=badhash"},
    )
    assert resp.status_code == 401


def test_hmac_body_tamper_rejected(client: TestClient, monkeypatch):
    """HMAC signed on original body must fail when body is changed."""
    monkeypatch.setattr("app.routes.webhook.settings", _hmac_settings())
    original = b'{"body":{"action":"authentik.core.auth.login_failed"}}'
    headers = _hmac_headers(original)
    tampered = b'{"body":{"action":"authentik.core.auth.logout"}}'
    resp = client.post("/webhook/authentik", content=tampered, headers=headers)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Unsigned mode
# ---------------------------------------------------------------------------


def test_unsigned_mode_accepted(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _unsigned_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200


def test_unsigned_mode_logs_loud_warning(client: TestClient, monkeypatch, caplog):
    monkeypatch.setattr("app.routes.webhook.settings", _unsigned_settings())
    with caplog.at_level(logging.WARNING, logger="app.routes.webhook"):
        client.post(
            "/webhook/authentik",
            content=_LOGOUT_BODY,
            headers={"Content-Type": "application/json"},
        )
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "unsigned" in messages.lower() or "without authentication" in messages.lower()


def test_bearer_mode_rejects_unsigned_request(client: TestClient, monkeypatch):
    """Default bearer mode must reject requests without Authorization."""
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Management token isolation
# ---------------------------------------------------------------------------


def test_management_token_not_accepted_as_webhook_bearer(client: TestClient, monkeypatch):
    """SSF_MANAGEMENT_TOKEN must not authenticate the webhook in bearer mode."""
    management_token = "test_management_token_min_32_chars_1234"
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.post(
        "/webhook/authentik",
        content=_LOGOUT_BODY,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {management_token}"},
    )
    assert resp.status_code == 401


def test_ssf_streams_still_requires_management_token(client: TestClient, monkeypatch):
    """Changing webhook auth mode must not affect management API protection."""
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.get("/ssf/streams")
    assert resp.status_code == 401


def test_jwks_remains_public(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.get("/jwks.json")
    assert resp.status_code == 200


def test_wellknown_remains_public(client: TestClient, monkeypatch):
    monkeypatch.setattr("app.routes.webhook.settings", _bearer_settings())
    resp = client.get("/.well-known/ssf-configuration")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_bearer_mode_without_token_raises():
    """bearer mode without SSF_WEBHOOK_TOKEN must raise RuntimeError at startup."""
    from app.config import _parse_webhook_token
    with pytest.raises(RuntimeError, match="SSF_WEBHOOK_TOKEN"):
        _parse_webhook_token(None, "bearer")


def test_bearer_mode_short_token_raises():
    from app.config import _parse_webhook_token
    with pytest.raises(RuntimeError, match="too short"):
        _parse_webhook_token("short", "bearer")


def test_invalid_auth_mode_raises():
    from app.config import _parse_webhook_auth_mode
    with pytest.raises(RuntimeError, match="SSF_WEBHOOK_AUTH_MODE"):
        _parse_webhook_auth_mode("ftp", False)


def test_hmac_mode_without_secret_raises():
    from app.config import _parse_webhook_secret
    with pytest.raises(RuntimeError, match="SSF_WEBHOOK_SECRET"):
        _parse_webhook_secret(None, "hmac")


def test_allow_unsigned_legacy_alias():
    """SSF_ALLOW_UNSIGNED_WEBHOOK=true maps to unsigned mode."""
    from app.config import _parse_webhook_auth_mode
    assert _parse_webhook_auth_mode(None, allow_unsigned_legacy=True) == "unsigned"
    assert _parse_webhook_auth_mode("bearer", allow_unsigned_legacy=True) == "unsigned"


def test_legacy_allow_unsigned_alias_logs_deprecation_warning(monkeypatch, caplog):
    """Preflight must warn when SSF_ALLOW_UNSIGNED_WEBHOOK=true is set."""
    import logging
    from unittest.mock import MagicMock, patch

    from app.startup import run_preflight_checks

    mock_settings = MagicMock(
        ssf_issuer="https://idp.example.com/shared-signals",
        ssf_base_url="https://idp.example.com/shared-signals",
        ssf_allow_custom_issuer=False,
        ssf_management_token="x" * 32,
        ssf_webhook_auth_mode="unsigned",
        ssf_webhook_token=None,
        ssf_webhook_secret="",
        keys_dir="",
        database_path="",
        apple_scim_enabled=False,
    )
    monkeypatch.setattr("app.startup.settings", mock_settings)
    monkeypatch.setenv("SSF_ALLOW_UNSIGNED_WEBHOOK", "true")

    with (
        patch("app.startup.Path") as mock_path,
        patch("app.startup.os.access", return_value=True),
        caplog.at_level(logging.WARNING, logger="app.startup"),
    ):
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        run_preflight_checks()

    warn_msgs = " ".join(r.getMessage() for r in caplog.records if r.levelno == logging.WARNING)
    assert "SSF_ALLOW_UNSIGNED_WEBHOOK" in warn_msgs
    assert "DEPRECATED" in warn_msgs or "deprecated" in warn_msgs.lower()
