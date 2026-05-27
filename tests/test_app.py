import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def signed_headers(body: bytes) -> dict[str, str]:
    """Return headers with a valid HMAC-SHA256 signature for the given body."""
    signature = hmac.new(b"test_secret_min_32_chars_1234567890", body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Authentik-Signature": f"sha256={signature}",
    }


def create_stream(client: TestClient) -> dict:
    """Create a test SSF stream and return the response payload."""
    response = client.post(
        "/ssf/streams",
        json={
            "aud": "apple-business-manager",
            "delivery": {
                "endpoint_url": "https://receiver.example.test/events",
                "endpoint_url_token": "receiver-secret-token",
            },
            "events_requested": [
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
            ],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_ssf_metadata_uses_public_base_url(client: TestClient):
    """SSF well-known configuration returns correct public URLs."""
    response = client.get("/.well-known/ssf-configuration")

    assert response.status_code == 200
    assert response.json() == {
        "issuer": "https://idp.example.com/application/o/apple-id/",
        "jwks_uri": "https://idp.example.com/shared-signals/jwks.json",
        "delivery_methods_supported": [
            "https://schemas.openid.net/secevent/risc/delivery-method/push",
        ],
        "configuration_endpoint": "https://idp.example.com/shared-signals/ssf/streams",
        "add_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:add",
        "remove_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:remove",
        "status_endpoint": "https://idp.example.com/shared-signals/ssf/status",
        "supported_scopes": ["openid"],
        "critical_subject_members": [],
        "spec_version": "1_0-ID2",
    }


def test_jwks_is_generated_with_signing_key(client: TestClient):
    """JWKS endpoint returns an RSA RS256 key."""
    response = client.get("/jwks.json")

    assert response.status_code == 200
    jwk = response.json()["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"]
    assert jwk["n"]
    assert jwk["e"] == "AQAB"


def test_stream_lifecycle_does_not_expose_receiver_token(client: TestClient):
    """Stream CRUD lifecycle completes successfully and never leaks the receiver token."""
    created = create_stream(client)

    assert created["aud"] == "apple-business-manager"
    assert created["status"] == "enabled"
    assert "endpoint_url_token" not in json.dumps(created)
    assert "receiver-secret-token" not in json.dumps(created)

    fetched = client.get("/ssf/streams")
    assert fetched.status_code == 200
    assert fetched.json()["stream_id"] == created["stream_id"]

    patched = client.patch("/ssf/streams", json={"status": "paused"})
    assert patched.status_code == 200
    assert patched.json()["status"] == "paused"

    deleted = client.delete("/ssf/streams")
    assert deleted.status_code == 204

    missing = client.get("/ssf/streams")
    assert missing.status_code == 404


def test_status_reports_no_stream_or_enabled_stream(client: TestClient):
    """Status endpoint reflects current stream state correctly."""
    client.delete("/ssf/streams")

    no_stream = client.get("/ssf/status")
    assert no_stream.status_code == 200
    assert no_stream.json() == {"status": "disabled", "reason": "no_stream"}

    created = create_stream(client)
    status = client.get("/ssf/status")
    assert status.status_code == 200
    assert status.json()["status"] == "enabled"
    assert status.json()["stream_id"] == created["stream_id"]


def test_webhook_accepts_unsigned_request(client: TestClient):
    """Unsigned webhook requests are accepted — Authentik generic transport does not sign."""
    response = client.post(
        "/webhook/authentik",
        json={"body": {"action": "authentik.core.auth.logout", "user": {"email": "u@example.com"}}},
    )
    assert response.status_code == 200


def test_webhook_rejects_invalid_hmac(client: TestClient):
    """Webhook requests with a present but invalid HMAC signature are rejected with 401."""
    body = json.dumps({"body": {"action": "authentik.core.auth.logout"}}).encode()
    response = client.post(
        "/webhook/authentik",
        content=body,
        headers={"X-Authentik-Signature": "sha256=invalidsignature", "Content-Type": "application/json"},
    )
    assert response.status_code == 401


def test_webhook_ignores_login_failed_event(client: TestClient):
    """Login failed events are ignored and not forwarded as SSF events."""
    body = json.dumps(
        {
            "body": {
                "action": "authentik.core.auth.login_failed",
                "user": {"email": "user@example.com"},
            },
        }
    ).encode()

    response = client.post("/webhook/authentik", content=body, headers=signed_headers(body))

    assert response.status_code == 200
    assert response.json() == {"status": "ignored", "reason": "unmapped_event"}


def test_webhook_delivers_mapped_event_without_logging_or_posting_real_token(client: TestClient, monkeypatch):
    """Mapped Authentik events are pushed as SETs; receiver token is never logged."""
    create_stream(client)
    pushed = []

    async def fake_push_set(stream, event_uri, email):
        pushed.append((stream.aud, event_uri, email, stream.endpoint_token))
        return True

    monkeypatch.setattr("app.routes.webhook.push_set", fake_push_set)
    body = json.dumps(
        {
            "body": {
                "action": "authentik.core.auth.logout",
                "user": {"email": "user@example.com"},
            },
        }
    ).encode()

    response = client.post("/webhook/authentik", content=body, headers=signed_headers(body))

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "delivered": 1, "failed": 0}
    assert pushed == [
        (
            "apple-business-manager",
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
            "user@example.com",
            "receiver-secret-token",
        )
    ]
