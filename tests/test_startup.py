"""Tests for app.startup.run_preflight_checks().

Each test calls run_preflight_checks() directly with a fully mocked settings
object and real (tmp_path) or mocked filesystem, then asserts the expected log
messages and exit behaviour.

The no_dns_mock marker tells conftest to skip the autouse mock_dns_resolve
fixture — run_preflight_checks() does no DNS lookups so it is unnecessary here.
"""

from __future__ import annotations

import logging
import time
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
        ssf_allowed_receiver_hosts=[],
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
        assert "SSF_ISSUER" in caplog.text
        assert "NOT SET" in caplog.text

    def test_ssf_base_url_missing(self, monkeypatch, caplog):
        monkeypatch.setattr("app.startup.settings", _good_settings(ssf_base_url=""))

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_BASE_URL" in caplog.text
        assert "NOT SET" in caplog.text

    def test_management_token_too_short(self, monkeypatch, caplog):
        monkeypatch.setattr("app.startup.settings", _good_settings(ssf_management_token="short"))

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_MANAGEMENT_TOKEN" in caplog.text
        assert "too short" in caplog.text


class TestPreflightWebhookAuth:
    def test_bearer_mode_token_too_short(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_webhook_auth_mode="bearer", ssf_webhook_token="short"),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_WEBHOOK_TOKEN" in caplog.text
        assert "too short" in caplog.text

    def test_bearer_mode_token_missing(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_webhook_auth_mode="bearer", ssf_webhook_token=""),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_WEBHOOK_TOKEN" in caplog.text
        assert "NOT SET" in caplog.text

    def test_hmac_mode_secret_missing(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_webhook_auth_mode="hmac", ssf_webhook_secret=""),
        )

        with pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "SSF_WEBHOOK_SECRET" in caplog.text
        assert "NOT SET" in caplog.text

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

        assert "not found" in caplog.text
        assert "will be generated" in caplog.text

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


class TestPreflightStoredStreams:
    def test_stored_stream_outside_allowlist_fails_preflight(self, monkeypatch, caplog, tmp_path):
        import sqlite3
        from contextlib import closing

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()
        db_file = tmp_path / "ssf.db"

        with closing(sqlite3.connect(db_file)) as con:
            con.execute(
                """
                CREATE TABLE streams (
                  stream_id TEXT PRIMARY KEY,
                  aud TEXT NOT NULL,
                  endpoint_url TEXT NOT NULL,
                  endpoint_token TEXT NOT NULL,
                  events_requested TEXT NOT NULL,
                  status TEXT DEFAULT 'enabled',
                  created_at INTEGER NOT NULL
                )
                """
            )
            con.execute(
                """
                INSERT INTO streams
                (stream_id, aud, endpoint_url, endpoint_token, events_requested, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "stream-1",
                    "aud",
                    "https://blocked.example.test/events",
                    "legacy-plaintext-token",
                    "[]",
                    "enabled",
                    1,
                ),
            )
            con.commit()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                keys_dir=str(keys_dir),
                database_path=str(db_file),
                ssf_allowed_receiver_hosts=["allowed.example.test"],
            ),
        )

        with patch("app.startup.os.access", return_value=True), pytest.raises(SystemExit) as exc_info:
            run_preflight_checks()

        assert exc_info.value.code == 0
        assert "outside SSF_ALLOWED_RECEIVER_HOSTS" in caplog.text

    def test_undecryptable_receiver_token_pauses_stream_and_allows_startup(self, monkeypatch, caplog, tmp_path):
        import dataclasses
        import sqlite3
        from contextlib import closing

        from app.config import settings as real_settings
        from app.crypto import encrypt_token

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()
        db_file = tmp_path / "ssf.db"
        stored = encrypt_token("receiver-token")

        with closing(sqlite3.connect(db_file)) as con:
            con.execute(
                """
                CREATE TABLE streams (
                  stream_id TEXT PRIMARY KEY,
                  aud TEXT NOT NULL,
                  endpoint_url TEXT NOT NULL,
                  endpoint_token TEXT NOT NULL,
                  events_requested TEXT NOT NULL,
                  status TEXT DEFAULT 'enabled',
                  created_at INTEGER NOT NULL
                )
                """
            )
            con.execute(
                """
                INSERT INTO streams
                (stream_id, aud, endpoint_url, endpoint_token, events_requested, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "stream-1",
                    "aud",
                    "https://receiver.example.test/events",
                    stored,
                    "[]",
                    "enabled",
                    1,
                ),
            )
            con.commit()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_file)),
        )
        monkeypatch.setattr(
            "app.crypto.settings",
            dataclasses.replace(
                real_settings,
                ssf_token_encryption_key=None,
                ssf_management_token="different_management_token_min_32_chars_12",
            ),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()
            from app.startup import quarantine_undecryptable_receiver_tokens

            quarantine_undecryptable_receiver_tokens()

        with closing(sqlite3.connect(db_file)) as con:
            row = con.execute(
                "SELECT status, endpoint_token FROM streams WHERE stream_id = ?",
                ("stream-1",),
            ).fetchone()

        assert row == ("paused", stored)
        assert "undecryptable endpoint tokens and were paused" in caplog.text
        assert "preflight OK" in caplog.text

    def test_quarantine_skips_when_database_file_missing(self, monkeypatch, caplog, tmp_path):
        from app.startup import quarantine_undecryptable_receiver_tokens

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_file = tmp_path / "missing.db"
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_file)),
        )

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            quarantine_undecryptable_receiver_tokens()

        assert "failed to validate/decrypt stored endpoint tokens" not in caplog.text
        assert not db_file.exists()

    def test_quarantine_logs_operational_error(self, monkeypatch, caplog, tmp_path):
        import sqlite3
        from unittest.mock import MagicMock

        from app.startup import quarantine_undecryptable_receiver_tokens

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_file = tmp_path / "ssf.db"
        db_file.touch()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_file)),
        )

        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        connection.execute.side_effect = sqlite3.OperationalError("database is locked")

        def _connect(*_args, **_kwargs):
            return connection

        monkeypatch.setattr("sqlite3.connect", _connect)

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            quarantine_undecryptable_receiver_tokens()

        assert "failed to validate/decrypt stored endpoint tokens" in caplog.text


class TestPreflightDeprecation:
    def test_allow_unsigned_webhook_legacy_alias_logs_deprecation(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                ssf_webhook_auth_mode="unsigned",
                ssf_webhook_token=None,
                ssf_webhook_secret="",
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
                ssf_allowed_receiver_hosts=[],
            ),
        )
        monkeypatch.setenv("SSF_ALLOW_UNSIGNED_WEBHOOK", "true")

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "SSF_ALLOW_UNSIGNED_WEBHOOK" in caplog.text
        assert "DEPRECATED" in caplog.text


class TestCheckScimAuthorized:
    def _tokens_db(self, tmp_path, expires_at: int | None):
        import sqlite3
        from contextlib import closing

        db_file = tmp_path / "scim.db"
        with closing(sqlite3.connect(db_file)) as con:
            con.execute(
                """
                CREATE TABLE apple_scim_tokens (
                  id INTEGER PRIMARY KEY, access_token TEXT NOT NULL,
                  refresh_token TEXT, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                )
                """
            )
            if expires_at is not None:
                con.execute(
                    "INSERT INTO apple_scim_tokens VALUES (1, 'tok', 'refresh', ?, 1)",
                    (expires_at,),
                )
            con.commit()
        return db_file

    def test_no_tokens_stored_warns(self, monkeypatch, caplog, tmp_path):
        from app.startup import _check_scim_authorized

        db_file = self._tokens_db(tmp_path, expires_at=None)
        monkeypatch.setattr("app.startup.settings", _good_settings(database_path=str(db_file)))

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            _check_scim_authorized()

        assert "not authorized" in caplog.text

    def test_stored_token_still_valid_logs_info(self, monkeypatch, caplog, tmp_path):
        from app.startup import _check_scim_authorized

        db_file = self._tokens_db(tmp_path, expires_at=int(time.time()) + 3600)
        monkeypatch.setattr("app.startup.settings", _good_settings(database_path=str(db_file)))

        with caplog.at_level(logging.INFO, logger="app.startup"):
            _check_scim_authorized()

        assert "authorized (token valid)" in caplog.text

    def test_stored_token_expired_warns(self, monkeypatch, caplog, tmp_path):
        from app.startup import _check_scim_authorized

        db_file = self._tokens_db(tmp_path, expires_at=1)  # far in the past
        monkeypatch.setattr("app.startup.settings", _good_settings(database_path=str(db_file)))

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            _check_scim_authorized()

        assert "token expired" in caplog.text

    def test_database_error_treated_as_not_authorized(self, monkeypatch, caplog, tmp_path):
        """A DB read failure (e.g. table doesn't exist yet) must not raise — just warn."""
        from app.startup import _check_scim_authorized

        monkeypatch.setattr("app.startup.settings", _good_settings(database_path=str(tmp_path / "nonexistent.db")))

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            _check_scim_authorized()

        assert "not authorized" in caplog.text


class TestCheckAuthentikConnectivity:
    def test_unreachable_warns(self, monkeypatch, caplog):
        import httpx

        from app.startup import _check_authentik_connectivity

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(authentik_url="https://authentik.example.test", authentik_token="tok"),
        )

        def _raise(*args, **kwargs):
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr("app.startup.httpx.get", _raise)

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            _check_authentik_connectivity()

        assert "unreachable" in caplog.text

    def test_success_logs_user_count(self, monkeypatch, caplog):
        from app.startup import _check_authentik_connectivity

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(authentik_url="https://authentik.example.test", authentik_token="tok"),
        )

        response = MagicMock(status_code=200)
        response.json.return_value = {"pagination": {"count": 42}}
        monkeypatch.setattr("app.startup.httpx.get", lambda *a, **k: response)

        with caplog.at_level(logging.INFO, logger="app.startup"):
            _check_authentik_connectivity()

        assert "connected, 42 users" in caplog.text

    def test_success_non_json_body_still_logs_connected(self, monkeypatch, caplog):
        from app.startup import _check_authentik_connectivity

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(authentik_url="https://authentik.example.test", authentik_token="tok"),
        )

        response = MagicMock(status_code=200, text="not json")
        response.json.side_effect = ValueError("not json")
        monkeypatch.setattr("app.startup.httpx.get", lambda *a, **k: response)

        with caplog.at_level(logging.INFO, logger="app.startup"):
            _check_authentik_connectivity()

        assert "connected" in caplog.text

    def test_auth_failure_logs_error(self, monkeypatch, caplog):
        from app.startup import _check_authentik_connectivity

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(authentik_url="https://authentik.example.test", authentik_token="bad-tok"),
        )

        response = MagicMock(status_code=401)
        monkeypatch.setattr("app.startup.httpx.get", lambda *a, **k: response)

        with caplog.at_level(logging.ERROR, logger="app.startup"):
            _check_authentik_connectivity()

        assert "AUTHENTIK_TOKEN" in caplog.text

    def test_unexpected_status_warns(self, monkeypatch, caplog):
        from app.startup import _check_authentik_connectivity

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(authentik_url="https://authentik.example.test", authentik_token="tok"),
        )

        response = MagicMock(status_code=503)
        monkeypatch.setattr("app.startup.httpx.get", lambda *a, **k: response)

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            _check_authentik_connectivity()

        assert "unexpected status" in caplog.text


class TestPreflightAppleScimSection:
    def _apple_scim_settings(self, tmp_path, **overrides):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()
        db_file = tmp_path / "ssf.db"
        db_file.touch()
        defaults = dict(
            keys_dir=str(keys_dir),
            database_path=str(db_file),
            apple_scim_enabled=True,
            apple_scim_sync_interval=3600,
            apple_scim_group_id=None,
            apple_scim_alert_webhook_url=None,
            apple_scim_authorize_url="https://appleid.apple.com/auth/oauth2/v2/authorize",
            apple_scim_token_url="https://appleid.apple.com/auth/oauth2/v2/token",
        )
        defaults.update(overrides)
        return _good_settings(**defaults)

    def test_enabled_without_group_filter_warns(self, monkeypatch, caplog, tmp_path):
        monkeypatch.setattr("app.startup.settings", self._apple_scim_settings(tmp_path))
        monkeypatch.setattr("app.startup._check_scim_authorized", lambda: None)
        monkeypatch.setattr("app.startup._check_authentik_connectivity", lambda: None)

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()

        assert "Apple SCIM             enabled" in caplog.text
        assert "group filter disabled" in caplog.text

    def test_enabled_with_group_filter_logs_group_id(self, monkeypatch, caplog, tmp_path):
        monkeypatch.setattr(
            "app.startup.settings",
            self._apple_scim_settings(tmp_path, apple_scim_group_id="978bff1a-5f55-4068-808c-45e09bb196d4"),
        )
        monkeypatch.setattr("app.startup._check_scim_authorized", lambda: None)
        monkeypatch.setattr("app.startup._check_authentik_connectivity", lambda: None)

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()

        assert "group filter enabled (APPLE_SCIM_GROUP_ID=978bff1a" in caplog.text

    def test_enabled_without_alert_webhook_warns(self, monkeypatch, caplog, tmp_path):
        monkeypatch.setattr("app.startup.settings", self._apple_scim_settings(tmp_path))
        monkeypatch.setattr("app.startup._check_scim_authorized", lambda: None)
        monkeypatch.setattr("app.startup._check_authentik_connectivity", lambda: None)

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "APPLE_SCIM_ALERT_WEBHOOK_URL not set" in caplog.text

    def test_enabled_with_alert_webhook_logs_configured(self, monkeypatch, caplog, tmp_path):
        monkeypatch.setattr(
            "app.startup.settings",
            self._apple_scim_settings(tmp_path, apple_scim_alert_webhook_url="https://hook.example.test"),
        )
        monkeypatch.setattr("app.startup._check_scim_authorized", lambda: None)
        monkeypatch.setattr("app.startup._check_authentik_connectivity", lambda: None)

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()

        assert "Apple SCIM alerts      webhook configured" in caplog.text

    def test_authorize_url_host_confusion_warning(self, monkeypatch, caplog, tmp_path):
        """appleaccount.apple.com is flagged — Apple Business UI currently expects appleid.apple.com."""
        monkeypatch.setattr(
            "app.startup.settings",
            self._apple_scim_settings(
                tmp_path,
                apple_scim_authorize_url="https://appleaccount.apple.com/auth/oauth2/v2/authorize",
            ),
        )
        monkeypatch.setattr("app.startup._check_scim_authorized", lambda: None)
        monkeypatch.setattr("app.startup._check_authentik_connectivity", lambda: None)

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "APPLE_SCIM_AUTHORIZE_URL uses appleaccount.apple.com" in caplog.text

    def test_disabled_warns_with_missing_vars(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()
        db_file = tmp_path / "ssf.db"
        db_file.touch()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                keys_dir=str(keys_dir),
                database_path=str(db_file),
                apple_scim_enabled=False,
                apple_scim_client_id=None,
                apple_scim_client_secret="set",
                authentik_url=None,
                authentik_token=None,
            ),
        )

        with patch("app.startup.os.access", return_value=True):
            run_preflight_checks()

        assert "Apple SCIM             disabled — missing:" in caplog.text
        assert "APPLE_SCIM_CLIENT_ID" in caplog.text
        assert "AUTHENTIK_URL" in caplog.text
        assert "AUTHENTIK_TOKEN" in caplog.text
        assert "APPLE_SCIM_CLIENT_SECRET" not in caplog.text.split("disabled — missing:")[1].split("\n")[0]


class TestPreflightForwardedIps:
    def test_wildcard_forwarded_ips_warns(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(keys_dir=str(keys_dir), database_path=str(db_dir / "ssf.db")),
        )
        monkeypatch.setenv("SSF_FORWARDED_ALLOW_IPS", "*")

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.WARNING, logger="app.startup"):
            run_preflight_checks()

        assert "trusting all X-Forwarded-For headers" in caplog.text


class TestCheckStoredStreamsAllowlist:
    def test_no_allowed_hosts_configured_short_circuits_true(self, monkeypatch):
        from app.startup import _check_stored_streams_allowlist

        monkeypatch.setattr("app.startup.settings", _good_settings(ssf_allowed_receiver_hosts=[]))

        assert _check_stored_streams_allowlist() is True

    def test_database_read_error_treated_as_pass(self, monkeypatch, tmp_path):
        """A DB read failure here must not itself fail preflight — it's a best-effort check."""
        from app.startup import _check_stored_streams_allowlist

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                ssf_allowed_receiver_hosts=["allowed.example.test"],
                database_path=str(tmp_path / "nonexistent.db" / "cant-be-a-dir"),
            ),
        )

        assert _check_stored_streams_allowlist() is True

    def test_all_stored_streams_within_allowlist_passes(self, monkeypatch, tmp_path):
        import sqlite3
        from contextlib import closing

        from app.startup import _check_stored_streams_allowlist

        db_file = tmp_path / "ssf.db"
        with closing(sqlite3.connect(db_file)) as con:
            con.execute(
                """
                CREATE TABLE streams (
                  stream_id TEXT PRIMARY KEY, aud TEXT NOT NULL, endpoint_url TEXT NOT NULL,
                  endpoint_token TEXT NOT NULL, events_requested TEXT NOT NULL,
                  status TEXT DEFAULT 'enabled', created_at INTEGER NOT NULL
                )
                """
            )
            con.execute(
                "INSERT INTO streams VALUES "
                "('s1', 'aud', 'https://allowed.example.test/events', 'tok', '[]', 'enabled', 1)"
            )
            con.commit()

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(ssf_allowed_receiver_hosts=["allowed.example.test"], database_path=str(db_file)),
        )

        assert _check_stored_streams_allowlist() is True


class TestQuarantineEdgeCases:
    def test_stream_with_empty_endpoint_token_is_skipped(self, monkeypatch, caplog, tmp_path):
        import sqlite3
        from contextlib import closing

        from app.startup import quarantine_undecryptable_receiver_tokens

        db_file = tmp_path / "ssf.db"
        with closing(sqlite3.connect(db_file)) as con:
            con.execute(
                """
                CREATE TABLE streams (
                  stream_id TEXT PRIMARY KEY, aud TEXT NOT NULL, endpoint_url TEXT NOT NULL,
                  endpoint_token TEXT NOT NULL, events_requested TEXT NOT NULL,
                  status TEXT DEFAULT 'enabled', created_at INTEGER NOT NULL
                )
                """
            )
            con.execute("INSERT INTO streams VALUES ('s1', 'aud', 'https://x.test/events', '', '[]', 'enabled', 1)")
            con.commit()

        monkeypatch.setattr("app.startup.settings", _good_settings(database_path=str(db_file)))

        with caplog.at_level(logging.WARNING, logger="app.startup"):
            quarantine_undecryptable_receiver_tokens()

        assert "undecryptable" not in caplog.text
        with closing(sqlite3.connect(db_file)) as con:
            status = con.execute("SELECT status FROM streams WHERE stream_id = 's1'").fetchone()[0]
        assert status == "enabled"

    def test_no_streams_table_returns_without_error(self, monkeypatch, tmp_path):
        from app.startup import quarantine_undecryptable_receiver_tokens

        db_file = tmp_path / "empty.db"
        db_file.touch()  # exists, but has no tables at all
        monkeypatch.setattr("app.startup.settings", _good_settings(database_path=str(db_file)))

        quarantine_undecryptable_receiver_tokens()  # must not raise


class TestPreflightIssuerWarnings:
    def test_issuer_matches_base_url_no_warning(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                ssf_issuer="https://idp.example.com/shared-signals",
                ssf_base_url="https://idp.example.com/shared-signals",
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
            ),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.WARNING, logger="app.startup"):
            run_preflight_checks()

        assert "differs from SSF_BASE_URL" not in caplog.text

    def test_issuer_looks_like_authentik_application_url_warns(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_allow_custom_issuer=False,
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
            ),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.WARNING, logger="app.startup"):
            run_preflight_checks()

        assert "looks like an Authentik OIDC application URL" in caplog.text

    def test_allow_custom_issuer_suppresses_all_issuer_warnings(self, monkeypatch, caplog, tmp_path):
        """SSF_ALLOW_CUSTOM_ISSUER=true skips both the mismatch and the Authentik-URL-shape checks."""
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                ssf_issuer="https://idp.example.com/application/o/apple-id/",
                ssf_base_url="https://idp.example.com/shared-signals",
                ssf_allow_custom_issuer=True,
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
            ),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.WARNING, logger="app.startup"):
            run_preflight_checks()

        assert "differs from SSF_BASE_URL" not in caplog.text
        assert "looks like an Authentik OIDC application URL" not in caplog.text


class TestPreflightWebhookBearerValid:
    def test_bearer_mode_valid_token_logs_configured(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                ssf_webhook_auth_mode="bearer",
                ssf_webhook_token="x" * 32,
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
            ),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()

        assert "SSF_WEBHOOK_TOKEN      configured (32 chars)" in caplog.text


class TestPreflightPiiPepper:
    def test_pii_pepper_configured_logs_info(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                pii_pepper="a-dedicated-pepper-value",
                keys_dir=str(keys_dir),
                database_path=str(db_dir / "ssf.db"),
            ),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()

        assert "SSF_PII_PEPPER         configured" in caplog.text

    def test_pii_pepper_not_configured_warns_about_fallback(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        db_dir = tmp_path / "db"
        db_dir.mkdir()
        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(pii_pepper=None, keys_dir=str(keys_dir), database_path=str(db_dir / "ssf.db")),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.WARNING, logger="app.startup"):
            run_preflight_checks()

        assert "SSF_PII_PEPPER         not set" in caplog.text
        assert "falling back to SSF_MANAGEMENT_TOKEN" in caplog.text


class TestPreflightAllowlistEndToEnd:
    def test_allowlist_configured_no_violations_passes(self, monkeypatch, caplog, tmp_path):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "private.pem").touch()
        (keys_dir / "jwks.json").touch()
        db_file = tmp_path / "ssf.db"
        db_file.touch()  # no streams table at all — nothing to violate

        monkeypatch.setattr(
            "app.startup.settings",
            _good_settings(
                keys_dir=str(keys_dir),
                database_path=str(db_file),
                ssf_allowed_receiver_hosts=["allowed.example.test"],
            ),
        )

        with patch("app.startup.os.access", return_value=True), caplog.at_level(logging.INFO, logger="app.startup"):
            run_preflight_checks()

        assert "preflight OK — starting" in caplog.text
        assert "Receiver allowlist     1 host(s): allowed.example.test" in caplog.text
