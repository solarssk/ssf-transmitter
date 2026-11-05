import hashlib
import hmac
import json
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import app.config as config
from app.main import app, create_app


@pytest.fixture
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


MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}


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
        headers=MGMT_HEADERS,
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
            "urn:ietf:rfc:8935",
        ],
        "configuration_endpoint": "https://idp.example.com/shared-signals/ssf/streams",
        "add_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:add",
        "remove_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:remove",
        "status_endpoint": "https://idp.example.com/shared-signals/ssf/status",
        "verification_endpoint": "https://idp.example.com/shared-signals/ssf/verification",
        "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6750"}],
        "critical_subject_members": [],
        "spec_version": "1_0",
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

    fetched = client.get("/ssf/streams", headers=MGMT_HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["stream_id"] == created["stream_id"]
    fetched_by_id = client.get(f"/ssf/streams/{created['stream_id']}", headers=MGMT_HEADERS)
    assert fetched_by_id.status_code == 200
    assert fetched_by_id.json()["stream_id"] == created["stream_id"]

    patched = client.patch("/ssf/streams", json={"status": "paused"}, headers=MGMT_HEADERS)
    assert patched.status_code == 200
    assert patched.json()["status"] == "paused"
    patched_by_id = client.patch(
        f"/ssf/streams/{created['stream_id']}",
        json={"status": "enabled"},
        headers=MGMT_HEADERS,
    )
    assert patched_by_id.status_code == 200
    assert patched_by_id.json()["status"] == "enabled"

    verify = client.post(f"/ssf/streams/{created['stream_id']}/verify", headers=MGMT_HEADERS)
    assert verify.status_code in (202, 502)
    by_id_status = client.get(f"/ssf/streams/{created['stream_id']}/status", headers=MGMT_HEADERS)
    assert by_id_status.status_code == 200
    assert by_id_status.json()["stream_id"] == created["stream_id"]

    deleted = client.delete("/ssf/streams", headers=MGMT_HEADERS)
    assert deleted.status_code == 204

    missing = client.get("/ssf/streams", headers=MGMT_HEADERS)
    assert missing.status_code == 404
    assert missing.json() == {"detail": "No stream configured"}


def test_status_reports_no_stream_or_enabled_stream(client: TestClient):
    """Status endpoint reflects current stream state correctly."""
    client.delete("/ssf/streams", headers=MGMT_HEADERS)

    no_stream = client.get("/ssf/status", headers=MGMT_HEADERS)
    assert no_stream.status_code == 200
    assert no_stream.json() == {"status": "disabled", "reason": "no_stream"}

    created = create_stream(client)
    status = client.get("/ssf/status", headers=MGMT_HEADERS)
    assert status.status_code == 200
    assert status.json()["status"] == "enabled"
    assert status.json()["stream_id"] == created["stream_id"]


def test_delivery_status_is_management_protected_and_exposes_only_counters(client: TestClient):
    unauthorized = client.get("/ssf/delivery/status")
    assert unauthorized.status_code == 401

    response = client.get("/ssf/delivery/status", headers=MGMT_HEADERS)
    assert response.status_code == 200
    assert set(response.json()) == {
        "pending",
        "blocked",
        "oldest_pending_at",
        "oldest_pending_age_seconds",
        "stored",
        "capacity",
    }


@pytest.mark.parametrize(
    ("method", "path", "handler", "field"),
    [
        ("POST", "/ssf/delivery/retry-blocked", "requeue_blocked_outbox", "requeued"),
        ("DELETE", "/ssf/delivery/pending", "delete_pending_outbox", "discarded"),
        ("DELETE", "/ssf/delivery/blocked", "delete_blocked_outbox", "discarded"),
    ],
)
def test_delivery_actions_require_management_auth_and_report_counts(client, monkeypatch, method, path, handler, field):
    """Queue mutations require management auth and report the affected count."""
    operation = AsyncMock(return_value=2)
    monkeypatch.setattr(f"app.routes.streams.{handler}", operation)

    assert client.request(method, path).status_code == 401
    response = client.request(method, path, headers=MGMT_HEADERS)

    assert response.status_code == 200
    assert response.json() == {field: 2}
    operation.assert_awaited_once_with()


def test_webhook_rejects_unsigned_request_by_default(client: TestClient):
    """Unsigned webhook requests are rejected with 401 (fail-closed by default)."""
    response = client.post(
        "/webhook/authentik",
        json={"body": {"action": "authentik.core.auth.logout", "user": {"email": "u@example.com"}}},
    )
    assert response.status_code == 401


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


def test_webhook_ignores_event_with_no_email(client: TestClient):
    """A mapped event with no user email is ignored — cannot build a SET without a subject email."""
    body = json.dumps({"body": {"action": "authentik.core.auth.logout"}}).encode()

    response = client.post("/webhook/authentik", content=body, headers=signed_headers(body))

    assert response.status_code == 200
    assert response.json() == {"status": "ignored", "reason": "missing_email"}


def test_webhook_ignores_event_when_no_stream_configured(client: TestClient):
    """A mapped event with an email but no SSF stream configured is ignored, not delivered."""
    client.delete("/ssf/streams", headers=MGMT_HEADERS)
    body = json.dumps(
        {"body": {"action": "authentik.core.auth.logout", "user": {"email": "user@example.com"}}}
    ).encode()

    response = client.post("/webhook/authentik", content=body, headers=signed_headers(body))

    assert response.status_code == 200
    assert response.json() == {"status": "ignored", "reason": "no_enabled_stream"}


def test_webhook_durably_queues_mapped_event(client: TestClient, monkeypatch):
    """A mapped event is acknowledged only after the durable queue accepts it."""
    create_stream(client)  # uses MGMT_HEADERS internally
    queued = []

    async def fake_enqueue_events(streams, events, email):
        queued.append((streams[0].aud, events[0].uri, email, streams[0].endpoint_token))
        return 1

    monkeypatch.setattr("app.routes.webhook.enqueue_events", fake_enqueue_events)
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
    assert response.json() == {"status": "accepted", "queued": 1}
    assert queued == [
        (
            "apple-business-manager",
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
            "user@example.com",
            "receiver-secret-token",
        )
    ]


def test_webhook_reports_zero_when_stream_filters_all_events(client: TestClient, monkeypatch):
    """A filtered event returns accepted with no SET signed or stored."""
    create_stream(client)
    monkeypatch.setattr("app.events.outbox.sign_set", lambda **kwargs: pytest.fail("unexpected signing"))
    body = json.dumps(
        {
            "body": {
                "action": "authentik.core.user.write",
                "user": {"email": "user@example.com"},
                "context": {"changed_fields": ["password"]},
            }
        }
    ).encode()

    response = client.post("/webhook/authentik", content=body, headers=signed_headers(body))

    assert response.status_code == 200
    assert response.json() == {"status": "accepted", "queued": 0}
    assert client.get("/ssf/delivery/status", headers=MGMT_HEADERS).json()["pending"] == 0


def test_webhook_returns_retryable_error_if_stream_changes_during_queueing(client: TestClient, monkeypatch):
    """A webhook is not acknowledged if its stream changed before persistence."""
    from app.database import StreamChangedError

    create_stream(client)

    async def stale_stream(*args):
        raise StreamChangedError("stream changed")

    monkeypatch.setattr("app.routes.webhook.enqueue_events", stale_stream)
    body = json.dumps(
        {"body": {"action": "authentik.core.auth.logout", "user": {"email": "user@example.com"}}}
    ).encode()

    response = client.post("/webhook/authentik", content=body, headers=signed_headers(body))

    assert response.status_code == 503
    assert "retry the webhook" in response.json()["detail"]


def test_webhook_returns_retryable_error_if_outbox_is_full(client: TestClient, monkeypatch):
    from app.database import OutboxFullError

    create_stream(client)

    async def full_queue(*args):
        raise OutboxFullError("full")

    monkeypatch.setattr("app.routes.webhook.enqueue_events", full_queue)
    body = json.dumps(
        {"body": {"action": "authentik.core.auth.logout", "user": {"email": "user@example.com"}}}
    ).encode()

    response = client.post("/webhook/authentik", content=body, headers=signed_headers(body))

    assert response.status_code == 503
    assert response.json()["detail"] == "Delivery queue is full; retry the webhook later"


def test_service_root_returns_json_discovery(client: TestClient):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "service": "SSF Transmitter",
        "version": "dev",
        "discovery": "/.well-known/ssf-configuration",
    }


def test_service_root_returns_html_for_browsers(client: TestClient):
    response = client.get("/", headers={"Accept": "text/html"})

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SSF Transmitter" in response.text
    assert "/.well-known/ssf-configuration" in response.text


def test_route_404_preserves_api_detail(client: TestClient):
    client.delete("/ssf/streams", headers=MGMT_HEADERS)

    response = client.post("/ssf/verification", headers=MGMT_HEADERS)

    assert response.status_code == 404
    assert response.json() == {"detail": "No stream configured"}


def test_unknown_path_returns_structured_json_404(client: TestClient):
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {
        "error": "not_found",
        "path": "/does-not-exist",
        "hint": "/.well-known/ssf-configuration",
    }


def test_unknown_path_returns_html_404_for_browsers(client: TestClient):
    response = client.get("/does-not-exist", headers={"Accept": "text/html"})

    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"]
    assert "Not Found" in response.text
    assert "/does-not-exist" in response.text


def test_openapi_docs_disabled_by_default(client: TestClient):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_openapi_docs_available_when_enabled(monkeypatch):
    monkeypatch.setattr(
        config,
        "settings",
        replace(config.settings, ssf_enable_openapi=True),
    )
    with TestClient(create_app()) as openapi_client:
        docs = openapi_client.get("/docs")
        schema = openapi_client.get("/openapi.json")

    assert docs.status_code == 200
    assert schema.status_code == 200
    assert schema.json()["info"]["version"] == "dev"
