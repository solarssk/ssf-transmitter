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
    assert stored.startswith("fernet1:")


def test_patch_preserves_undecryptable_receiver_token_without_replacement(client: TestClient, monkeypatch):
    """Unrelated stream patches must not erase a token encrypted with an old key."""
    import dataclasses
    import sqlite3
    from contextlib import closing

    from app.config import settings as real_settings

    _create_stream(client, token="receiver-token-before-rotation")

    with closing(sqlite3.connect(real_settings.database_path)) as con:
        row = con.execute("SELECT endpoint_token FROM streams LIMIT 1").fetchone()
    assert row is not None
    stored = row[0]

    monkeypatch.setattr(
        "app.crypto.settings",
        dataclasses.replace(
            real_settings,
            ssf_token_encryption_key=None,
            ssf_management_token="different_management_token_min_32_chars_12",
        ),
    )

    resp = client.patch("/ssf/streams", json={"status": "paused"}, headers=MGMT_HEADERS)

    assert resp.status_code == 200
    with closing(sqlite3.connect(real_settings.database_path)) as con:
        row = con.execute("SELECT status, endpoint_token FROM streams LIMIT 1").fetchone()
    assert row == ("paused", stored)


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
    assert encrypted.startswith("fernet1:")
    assert decrypt_token(encrypted) == token


def test_decrypt_token_raises_when_fernet_blob_decrypted_with_wrong_key(caplog, monkeypatch):
    """Changing encryption key must fail decrypt instead of returning ciphertext as bearer token."""
    import dataclasses

    from app.config import settings as real_settings
    from app.crypto import TokenDecryptionError, decrypt_token, encrypt_token

    token = "receiver-bearer-token-value"
    encrypted = encrypt_token(token)

    monkeypatch.setattr(
        "app.crypto.settings",
        dataclasses.replace(
            real_settings,
            ssf_token_encryption_key=None,
            ssf_management_token="different_management_token_min_32_chars_12",
        ),
    )

    with caplog.at_level("WARNING", logger="app.crypto"), pytest.raises(TokenDecryptionError):
        decrypt_token(encrypted)

    assert "SSF_TOKEN_ENCRYPTION_KEY or SSF_MANAGEMENT_TOKEN may have changed" in caplog.text


def test_legacy_prefixed_fernet_blob_without_version_prefix_still_decrypts():
    """Tokens encrypted before the fernet1: prefix remain readable."""
    from app.crypto import decrypt_token, encrypt_token

    token = "receiver-bearer-token-value"
    legacy_blob = encrypt_token(token).removeprefix("fernet1:")
    assert decrypt_token(legacy_blob) == token


def test_unprefixed_100_char_fernet_ciphertext_still_decrypts():
    """Short plaintext tokens produce 100-char Fernet blobs that must still decrypt."""
    from app.crypto import decrypt_token, encrypt_token

    token = "x" * 15
    legacy_blob = encrypt_token(token).removeprefix("fernet1:")
    assert len(legacy_blob) == 100
    assert decrypt_token(legacy_blob) == token


def test_legacy_plaintext_matching_gAAAA_heuristic_not_treated_as_fernet():
    """Long plaintext bearer tokens must not be mistaken for SSF-owned ciphertext."""
    from app.crypto import decrypt_token

    plaintext = "gAAAA" + ("!" * 100)
    assert decrypt_token(plaintext) == plaintext


def test_fernet_shaped_plaintext_bearer_token_preserved_on_decrypt_failure(monkeypatch):
    """Receiver bearer tokens that look like Fernet must not break startup or delivery."""
    import dataclasses

    from app.config import settings as real_settings
    from app.crypto import decrypt_token, encrypt_token

    token = "receiver-bearer-token-value"
    fernet_shaped = encrypt_token(token).removeprefix("fernet1:")

    monkeypatch.setattr(
        "app.crypto.settings",
        dataclasses.replace(
            real_settings,
            ssf_token_encryption_key=None,
            ssf_management_token="different_management_token_min_32_chars_12",
        ),
    )

    assert decrypt_token(fernet_shaped) == fernet_shaped


def test_legacy_plaintext_bearer_with_fernet1_prefix_preserved():
    """Pre-upgrade plaintext tokens starting with fernet1: must not break delivery."""
    from app.crypto import decrypt_token

    plaintext = "fernet1:receiver-supplied-bearer-token"
    assert decrypt_token(plaintext) == plaintext


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
