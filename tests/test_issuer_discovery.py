"""Tests for SSF_ISSUER validation warnings and SSF discovery document."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from app.startup import run_preflight_checks

pytestmark = pytest.mark.no_dns_mock


def _settings(**overrides):
    defaults = dict(
        ssf_issuer="https://idp.example.com/shared-signals",
        ssf_base_url="https://idp.example.com/shared-signals",
        ssf_allow_custom_issuer=False,
        ssf_management_token="x" * 32,
        ssf_webhook_auth_mode="bearer",
        ssf_webhook_token="x" * 32,
        ssf_webhook_secret="",
        pii_pepper="",
        keys_dir="",
        database_path="",
        apple_scim_enabled=False,
    )
    defaults.update(overrides)
    return MagicMock(**defaults)


# ---------------------------------------------------------------------------
# Startup issuer warnings
# ---------------------------------------------------------------------------


def test_startup_no_warning_when_issuer_matches_base_url(monkeypatch, caplog):
    monkeypatch.setattr("app.startup.settings", _settings())

    with patch("app.startup.Path") as mock_path:
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

    warn_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert not any("SSF_ISSUER" in m and "differs" in m for m in warn_msgs)


def test_startup_warns_when_issuer_differs_from_base_url(monkeypatch, caplog):
    monkeypatch.setattr(
        "app.startup.settings",
        _settings(
            ssf_issuer="https://idp.example.com/application/o/apple-id/",
            ssf_base_url="https://idp.example.com/shared-signals",
        ),
    )

    with patch("app.startup.Path") as mock_path:
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

    assert any("SSF_ISSUER" in r.getMessage() and "differs" in r.getMessage()
               for r in caplog.records if r.levelno == logging.WARNING)


def test_startup_warns_on_oidc_looking_issuer(monkeypatch, caplog):
    monkeypatch.setattr(
        "app.startup.settings",
        _settings(
            ssf_issuer="https://idp.example.com/application/o/apple-id/",
            ssf_base_url="https://idp.example.com/shared-signals",
        ),
    )

    with patch("app.startup.Path") as mock_path:
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

    assert any("/application/o/" in r.getMessage() or "OIDC" in r.getMessage()
               for r in caplog.records if r.levelno == logging.WARNING)


def test_startup_allow_custom_issuer_suppresses_warning(monkeypatch, caplog):
    monkeypatch.setattr(
        "app.startup.settings",
        _settings(
            ssf_issuer="https://idp.example.com/application/o/apple-id/",
            ssf_base_url="https://idp.example.com/shared-signals",
            ssf_allow_custom_issuer=True,
        ),
    )

    with patch("app.startup.Path") as mock_path:
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

    warn_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert not any("SSF_ISSUER" in m and ("differs" in m or "OIDC" in m or "application/o" in m)
                   for m in warn_msgs)


def test_startup_does_not_exit_on_mismatched_issuer(monkeypatch):
    monkeypatch.setattr(
        "app.startup.settings",
        _settings(
            ssf_issuer="https://idp.example.com/application/o/apple-id/",
            ssf_base_url="https://idp.example.com/shared-signals",
        ),
    )

    with patch("app.startup.Path") as mock_path:
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()  # must not raise SystemExit


# ---------------------------------------------------------------------------
# Discovery document
# ---------------------------------------------------------------------------


def test_wellknown_includes_verification_endpoint():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/.well-known/ssf-configuration")

    assert resp.status_code == 200
    assert "verification_endpoint" in resp.json()


def test_wellknown_verification_endpoint_under_base_url():
    from fastapi.testclient import TestClient

    from app.config import settings
    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/.well-known/ssf-configuration")

    data = resp.json()
    assert data["verification_endpoint"].startswith(settings.ssf_base_url)


def test_wellknown_all_urls_under_ssf_base_url():
    from fastapi.testclient import TestClient

    from app.config import settings
    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/.well-known/ssf-configuration")

    data = resp.json()
    url_fields = [
        "jwks_uri", "configuration_endpoint", "add_subject_endpoint",
        "remove_subject_endpoint", "status_endpoint", "verification_endpoint",
    ]
    for field in url_fields:
        assert data[field].startswith(settings.ssf_base_url), (
            f"{field}={data[field]!r} does not start with SSF_BASE_URL={settings.ssf_base_url!r}"
        )


def test_wellknown_no_openid_scopes():
    """supported_scopes must not claim OpenID — OAuth2 is not implemented."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/.well-known/ssf-configuration")

    data = resp.json()
    assert "supported_scopes" not in data or "openid" not in data.get("supported_scopes", [])


def test_wellknown_authorization_schemes():
    """CAEP Interoperability Profile requires authorization_schemes with OAuth2 URN."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/.well-known/ssf-configuration")

    data = resp.json()
    assert "authorization_schemes" in data
    urns = [s.get("spec_urn") for s in data["authorization_schemes"]]
    assert "urn:ietf:rfc:6749" in urns


# ---------------------------------------------------------------------------
# SSF_PII_PEPPER warnings
# ---------------------------------------------------------------------------


def test_startup_warns_when_pii_pepper_not_set(monkeypatch, caplog):
    monkeypatch.setattr("app.startup.settings", _settings(pii_pepper=""))

    with patch("app.startup.Path") as mock_path:
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

    assert any(
        "SSF_PII_PEPPER" in r.getMessage() and "falling back" in r.getMessage()
        for r in caplog.records if r.levelno == logging.WARNING
    )


def test_startup_no_pii_pepper_warning_when_set(monkeypatch, caplog):
    monkeypatch.setattr("app.startup.settings", _settings(pii_pepper="dedicated-pepper-secret"))

    with patch("app.startup.Path") as mock_path:
        mock_path.return_value.__truediv__ = lambda s, x: MagicMock(exists=lambda: True)
        mock_path.return_value.parent.exists.return_value = True
        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

    assert not any(
        "SSF_PII_PEPPER" in r.getMessage() and "falling back" in r.getMessage()
        for r in caplog.records if r.levelno == logging.WARNING
    )
