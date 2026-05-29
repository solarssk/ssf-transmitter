"""Tests for app.startup.run_preflight_checks().

These tests import run_preflight_checks directly and exercise each check branch
with mocked settings, filesystem, and sys.exit. The mock_dns_resolve fixture
in conftest.py is skipped for this module to avoid import issues.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from app.startup import run_preflight_checks


class TestPreflightConfigValidation:
    """Test configuration validation checks."""

    def test_ssf_issuer_missing(self, monkeypatch, caplog):
        """Fail when SSF_ISSUER is not set."""
        monkeypatch.delenv("SSF_ISSUER", raising=False)
        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir="/tmp/keys",
                database_path="/tmp/ssf.db",
                apple_scim_enabled=False,
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "NOT SET" in caplog.text and "SSF_ISSUER" in caplog.text

    def test_ssf_base_url_missing(self, monkeypatch, caplog):
        """Fail when SSF_BASE_URL is not set."""
        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir="/tmp/keys",
                database_path="/tmp/ssf.db",
                apple_scim_enabled=False,
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "NOT SET" in caplog.text and "SSF_BASE_URL" in caplog.text

    def test_management_token_too_short(self, monkeypatch, caplog):
        """Fail when SSF_MANAGEMENT_TOKEN is too short."""
        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="short",
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir="/tmp/keys",
                database_path="/tmp/ssf.db",
                apple_scim_enabled=False,
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "too short" in caplog.text and "SSF_MANAGEMENT_TOKEN" in caplog.text


class TestPreflightWebhookAuth:
    """Test webhook authentication mode validation."""

    def test_bearer_mode_token_too_short(self, monkeypatch, caplog):
        """Fail in bearer mode when SSF_WEBHOOK_TOKEN is too short."""
        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="bearer",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="short",
                keys_dir="/tmp/keys",
                database_path="/tmp/ssf.db",
                apple_scim_enabled=False,
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "too short" in caplog.text and "SSF_WEBHOOK_TOKEN" in caplog.text

    def test_bearer_mode_token_missing(self, monkeypatch, caplog):
        """Fail in bearer mode when SSF_WEBHOOK_TOKEN is not set."""
        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="bearer",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="",
                keys_dir="/tmp/keys",
                database_path="/tmp/ssf.db",
                apple_scim_enabled=False,
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "NOT SET" in caplog.text and "SSF_WEBHOOK_TOKEN" in caplog.text

    def test_hmac_mode_secret_missing(self, monkeypatch, caplog):
        """Fail in hmac mode when SSF_WEBHOOK_SECRET is not set."""
        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="",
                ssf_webhook_token="x" * 32,
                keys_dir="/tmp/keys",
                database_path="/tmp/ssf.db",
                apple_scim_enabled=False,
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "NOT SET" in caplog.text and "SSF_WEBHOOK_SECRET" in caplog.text

    def test_unsigned_mode_warning(self, monkeypatch, caplog):
        """Warn in unsigned mode but pass preflight."""
        with patch("app.startup.Path"):
            monkeypatch.setattr(
                "app.startup.settings",
                MagicMock(
                    ssf_issuer="https://idp.example.com/application/o/apple-id/",
                    ssf_base_url="https://idp.example.com/shared-signals",
                    ssf_management_token="x" * 32,
                    ssf_webhook_auth_mode="unsigned",
                    ssf_webhook_secret="",
                    ssf_webhook_token="",
                    keys_dir="/tmp/keys",
                    database_path="/tmp/ssf.db",
                    apple_scim_enabled=False,
                ),
            )

            with patch("app.startup.os.access", return_value=True):
                with patch("app.startup.Path") as mock_path:
                    mock_path.return_value.exists.return_value = False
                    run_preflight_checks()

            assert "unsigned" in caplog.text

    def test_unknown_auth_mode(self, monkeypatch, caplog):
        """Fail when webhook auth mode is unknown."""
        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="invalid_mode",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir="/tmp/keys",
                database_path="/tmp/ssf.db",
                apple_scim_enabled=False,
            ),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "unknown value" in caplog.text


class TestPreflightLocalResources:
    """Test local filesystem resource checks."""

    def test_database_dir_not_writable(self, monkeypatch, caplog, tmp_path):
        """Fail when database directory is not writable."""
        read_only_dir = tmp_path / "readonly"
        read_only_dir.mkdir()

        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir=str(tmp_path / "keys"),
                database_path=str(read_only_dir / "ssf.db"),
                apple_scim_enabled=False,
            ),
        )

        # Mock os.access to return False for directory write check
        with patch("app.startup.os.access") as mock_access:
            mock_access.return_value = False

            with pytest.raises(SystemExit) as exc_info:
                run_preflight_checks()

            assert exc_info.value.code == 0
            assert "not writable" in caplog.text

    def test_database_file_not_writable(self, monkeypatch, caplog, tmp_path):
        """Fail when existing database file is not writable."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()

        db_file = tmp_path / "ssf.db"
        db_file.write_text("test")

        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir=str(keys_dir),
                database_path=str(db_file),
                apple_scim_enabled=False,
            ),
        )

        with patch("app.startup.os.access") as mock_access:
            # First call (dir check) returns True, second call (file check) returns False
            mock_access.side_effect = [True, False]

            with pytest.raises(SystemExit) as exc_info:
                run_preflight_checks()

            assert exc_info.value.code == 0
            assert "not writable" in caplog.text

    def test_missing_signing_key_warns(self, monkeypatch, caplog, tmp_path):
        """Warn when signing key doesn't exist (will be generated)."""
        # Create directory without key files
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        db_dir = tmp_path / "db"
        db_dir.mkdir()

        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
                apple_scim_enabled=False,
            ),
        )

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "not found" in caplog.text and "will be generated" in caplog.text


class TestPreflightSuccess:
    """Test successful preflight completion."""

    def test_all_checks_pass(self, monkeypatch, caplog, tmp_path):
        """Pass when all checks succeed."""
        # Create all required files and directories
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()

        db_dir = tmp_path / "db"
        db_dir.mkdir()
        db_file = db_dir / "ssf.db"
        db_file.touch()

        monkeypatch.setattr(
            "app.startup.settings",
            MagicMock(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_management_token="x" * 32,
                ssf_webhook_auth_mode="hmac",
                ssf_webhook_secret="x" * 32,
                ssf_webhook_token="x" * 32,
                keys_dir=str(keys_dir),
                database_path=str(db_file),
                apple_scim_enabled=False,
            ),
        )

        with patch("app.startup.os.access", return_value=True):
            with caplog.at_level(logging.INFO):
                run_preflight_checks()

        assert "preflight OK — starting" in caplog.text
