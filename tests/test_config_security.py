"""Tests for security-related configuration parsing."""

from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, _parse_allowed_receiver_hosts, _parse_log_level
from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as tc:
        yield tc


def test_parse_allowed_receiver_hosts_normalizes():
    assert _parse_allowed_receiver_hosts("Foo.Example.COM, bar.example.com") == [
        "foo.example.com",
        "bar.example.com",
    ]


def test_parse_log_level_accepts_ssf_log_level_values():
    assert _parse_log_level("debug") == "DEBUG"
    assert _parse_log_level("INFO") == "INFO"


def test_parse_log_level_rejects_invalid():
    with pytest.raises(ValueError, match="SSF_LOG_LEVEL"):
        _parse_log_level("TRACE")


def test_from_env_reads_ssf_log_level(monkeypatch):
    monkeypatch.setenv("SSF_ISSUER", "https://idp.example.com/shared-signals")
    monkeypatch.setenv("SSF_BASE_URL", "https://idp.example.com/shared-signals")
    monkeypatch.setenv("SSF_MANAGEMENT_TOKEN", "test_management_token_min_32_chars_1234")
    monkeypatch.setenv("SSF_WEBHOOK_TOKEN", "test_webhook_token_min_32_chars_1234567")
    monkeypatch.setenv("SSF_LOG_LEVEL", "DEBUG")
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    cfg = Settings.from_env()
    assert cfg.log_level == "DEBUG"


def test_from_env_rejects_non_https_issuer(monkeypatch):
    monkeypatch.setenv("SSF_ISSUER", "http://idp.example.com/shared-signals")
    monkeypatch.setenv("SSF_BASE_URL", "https://idp.example.com/shared-signals")
    monkeypatch.setenv("SSF_MANAGEMENT_TOKEN", "test_management_token_min_32_chars_1234")
    monkeypatch.setenv("SSF_WEBHOOK_TOKEN", "test_webhook_token_min_32_chars_1234567")
    with pytest.raises(RuntimeError, match="SSF_ISSUER"):
        Settings.from_env()


def test_authentik_url_none_when_unset(monkeypatch):
    monkeypatch.setenv("SSF_ISSUER", "https://idp.example.com/shared-signals")
    monkeypatch.setenv("SSF_BASE_URL", "https://idp.example.com/shared-signals")
    monkeypatch.setenv("SSF_MANAGEMENT_TOKEN", "test_management_token_min_32_chars_1234")
    monkeypatch.setenv("SSF_WEBHOOK_TOKEN", "test_webhook_token_min_32_chars_1234567")
    monkeypatch.delenv("AUTHENTIK_URL", raising=False)
    cfg = Settings.from_env()
    assert cfg.authentik_url is None
    assert cfg.apple_scim_enabled is False


def test_stream_rejected_when_host_not_in_allowlist(client, monkeypatch):
    """POST /ssf/streams rejects hosts outside SSF_ALLOWED_RECEIVER_HOSTS."""
    from app.config import settings as real_settings

    monkeypatch.setattr(
        "app.routes.streams.settings",
        dataclasses.replace(
            real_settings,
            ssf_allowed_receiver_hosts=["allowed.example.com"],
        ),
    )
    resp = client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {"endpoint_url": "https://other.example.test/events"},
        },
        headers={"Authorization": "Bearer test_management_token_min_32_chars_1234"},
    )
    assert resp.status_code == 400
    assert "allowlist" in resp.json()["detail"].lower()
