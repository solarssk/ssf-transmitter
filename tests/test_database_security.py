"""Tests for database security properties.

Verifies that:
- The receiver endpoint token is never returned by any API endpoint.
- The database file is created with 0600 permissions.
"""

from __future__ import annotations

import json
import os
import stat

import pytest
from fastapi.testclient import TestClient

from app.main import app

MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}


@pytest.fixture()
def client():
    with TestClient(app) as tc:
        yield tc


# ---------------------------------------------------------------------------
# Receiver token never exposed via API
# ---------------------------------------------------------------------------


def _create_stream(client: TestClient, token: str = "super-secret-receiver-token") -> dict:
    resp = client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://receiver.example.test/events",
                "endpoint_url_token": token,
            },
        },
        headers=MGMT_HEADERS,
    )
    assert resp.status_code == 201
    return resp.json()


def test_create_response_does_not_leak_token(client: TestClient):
    token = "super-secret-create-token-xyz"
    body = _create_stream(client, token=token)
    assert token not in json.dumps(body)


def test_get_response_does_not_leak_token(client: TestClient):
    token = "super-secret-get-token-xyz"
    _create_stream(client, token=token)
    resp = client.get("/ssf/streams", headers=MGMT_HEADERS)
    assert resp.status_code == 200
    assert token not in json.dumps(resp.json())


def test_patch_response_does_not_leak_token(client: TestClient):
    token = "super-secret-patch-token-xyz"
    _create_stream(client, token=token)
    resp = client.patch("/ssf/streams", json={"status": "paused"}, headers=MGMT_HEADERS)
    assert resp.status_code == 200
    assert token not in json.dumps(resp.json())


def test_status_response_does_not_leak_token(client: TestClient):
    token = "super-secret-status-token-xyz"
    _create_stream(client, token=token)
    resp = client.get("/ssf/status", headers=MGMT_HEADERS)
    assert resp.status_code == 200
    assert token not in json.dumps(resp.json())


def test_token_encrypted_at_rest_in_sqlite(client: TestClient):
    """Receiver token must not appear as plaintext in the SQLite file."""
    import sqlite3
    from contextlib import closing

    from app.config import settings

    token = "super-secret-at-rest-token-xyz"
    _create_stream(client, token=token)

    with closing(sqlite3.connect(settings.database_path)) as con:
        row = con.execute("SELECT endpoint_token FROM streams LIMIT 1").fetchone()
    assert row is not None
    stored = row[0]
    assert stored != token
    assert token not in stored


def test_legacy_plaintext_token_decrypt_fallback():
    """Pre-upgrade plaintext tokens are returned as-is when Fernet decrypt fails."""
    from app.crypto import decrypt_token

    plaintext = "legacy-plaintext-receiver-token"
    assert decrypt_token(plaintext) == plaintext


def test_encrypt_decrypt_roundtrip():
    from app.crypto import decrypt_token, encrypt_token

    token = "receiver-bearer-token-value"
    encrypted = encrypt_token(token)
    assert encrypted != token
    assert decrypt_token(encrypted) == token


# ---------------------------------------------------------------------------
# Database file permissions
# ---------------------------------------------------------------------------


def test_database_file_has_0600_permissions(client: TestClient):
    """The SQLite database file must be created with owner-only read/write (0600)."""
    from app.config import settings

    db_path = settings.database_path
    if not os.path.exists(db_path):
        pytest.skip("Database file does not exist (in-memory or not yet initialised)")

    file_stat = os.stat(db_path)
    mode = stat.S_IMODE(file_stat.st_mode)
    # Allow 0600 (owner read+write, no group/other access)
    assert mode == 0o600, (
        f"Database file {db_path} has permissions {oct(mode)}, expected 0o600. "
        "Receiver tokens stored in this file are accessible to other processes."
    )
