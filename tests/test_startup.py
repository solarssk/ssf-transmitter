"""Tests for app.startup.run_preflight_checks().

Each test calls run_preflight_checks() directly with a fully mocked settings
object and real (tmp_path) or mocked filesystem, then asserts the expected log
messages and exit behaviour.

The no_dns_mock marker tells conftest to skip the autouse mock_dns_resolve
fixture — run_preflight_checks() does no DNS lookups so it is unnecessary here.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from app.startup import run_preflight_checks

pytestmark = pytest.mark.no_dns_mock


def _good_settings(**overrides):
    """Return a MagicMock settings object with all checks passing."""
    defaults = dict(
        ssf_issuer="https://idp.example.com/shared-signals",
        ssf_base_url="https://idp.example.com/shared-signals",
        ssf_allow_custom_issuer=False,
        ssf_management_token="x" * 32,
        ssf_webhook_auth_mode="hmac",
        ssf_webhook_secret="x" * 32,
        ssf_webhook_token="x" * 32,
        keys_dir="",  # overridden per-test when filesystem matters
        database_path="",  # overridden per-test when filesystem matters
        apple_scim_enabled=False,
    )
    defaults.update(overrides)
    return MagicMock(**defaults)


class TestPreflightConfigValidation:
    def test_ssf_issuer_missing(self, monkeypatch, caplog):
        monkeypatch.setattr("app.startup.settings", _good_settings(ssf_issuer=""))

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_ISSUER" in caplog.text and "NOT SET" in caplog.text

    def test_ssf_base_url_missing(self, monkeypatch, caplog):
        monkeypatch.setattr("app.startup.settings", _good_settings(ssf_base_url=""))

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_BASE_URL" in caplog.text and "NOT SET" in caplog.text

    def test_management_token_too_short(self, monkeypatch, caplog):
        monkeypatch.setattr("app.startup.settings", _good_settings(ssf_management_token="short"))

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_MANAGEMENT_TOKEN" in caplog.text and "too short" in caplog.text


class TestPreflightWebhookAuth:
    def test_bearer_mode_token_too_short(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_webhook_auth_mode="bearer", ssf_webhook_token="short"),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_WEBHOOK_TOKEN" in caplog.text and "too short" in caplog.text

    def test_bearer_mode_token_missing(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_webhook_auth_mode="bearer", ssf_webhook_token=""),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_WEBHOOK_TOKEN" in caplog.text and "NOT SET" in caplog.text

    def test_hmac_mode_secret_missing(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_webhook_auth_mode="hmac", ssf_webhook_secret=""),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_WEBHOOK_SECRET" in caplog.text and "NOT SET" in caplog.text

    def test_unsigned_mode_emits_warning(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                ssf_webhook_auth_mode="unsigned",
                ssf_webhook_secret="",
                ssf_webhook_token="",
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
            ),
        )

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "unsigned" in caplog.text

    def test_unknown_auth_mode(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_webhook_auth_mode="invalid_mode"),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "unknown value" in caplog.text


class TestPreflightLocalResources:
    def test_missing_signing_key_warns(self, monkeypatch, caplog, tmp_path):
        """Keys dir exists but no key files — non-fatal, warns only."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_dir / "ssf.db")),
        )

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "not found" in caplog.text and "will be generated" in caplog.text

    def test_database_dir_missing_warns(self, monkeypatch, caplog, tmp_path):
        """DB parent directory doesn't exist yet — non-fatal, warns only."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                keys_dir=str(keys_dir),
                database_path=str(tmp_path / "nonexistent" / "ssf.db"),
            ),
        )

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "does not exist yet" in caplog.text

    def test_database_dir_not_writable(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_dir / "ssf.db")),
        )

        with patch("app.startup.os.access", return_value=False), pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "not writable" in caplog.text

    def test_database_file_not_writable(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()
        db_file = tmp_path / "ssf.db"
        db_file.write_text("db")

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_file)),
        )

        # dir is writable, file is not
        with patch("app.startup.os.access", side_effect=[True, False]), pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "not writable" in caplog.text


class TestPreflightSuccess:
    def test_all_checks_pass(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()
        db_file = tmp_path / "ssf.db"
        db_file.touch()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_file)),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()

        assert "preflight OK — starting" in caplog.text
