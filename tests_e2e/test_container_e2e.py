"""End-to-end tests against a running instance of the built Docker image.

Exercises discovery, JWKS, the management API's stream CRUD, and the
Authentik webhook receiver over real HTTP — things an in-process TestClient
can't catch: a broken CMD/entrypoint, a runtime-missing dependency, the
container's actual uvicorn/ASGI wiring, real DNS resolution for SSRF
checks, and so on. See tests_e2e/conftest.py for how to point this at a
running container.

A full successful stream-creation round-trip (201, not just the negative
cases) is deliberately not covered here: creating a stream requires the
verification SET push to succeed against delivery.endpoint_url, and the
SSRF protection this container correctly enforces blocks every reachable
target in a CI network by design — loopback, the Docker bridge's RFC1918
range, and host.docker.internal's private gateway address are all in
_BLOCKED_NETWORKS. Testing the happy path for real would need a receiver
at a genuine public HTTPS endpoint, which is out of scope for a
self-contained CI job. test_url_validation.py and test_database_security.py
already cover the full create/patch/delete lifecycle against the in-process
app with push_verification_set mocked.
"""

from __future__ import annotations

import httpx

from tests_e2e.conftest import MGMT_HEADERS, WEBHOOK_HEADERS

# ---------------------------------------------------------------------------
# Discovery / public endpoints — no auth, no state
# ---------------------------------------------------------------------------


def test_root_returns_service_info(client: httpx.Client):
    resp = client.get("/", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "SSF Transmitter"
    assert body["discovery"] == "/.well-known/ssf-configuration"


def test_wellknown_configuration(client: httpx.Client):
    resp = client.get("/.well-known/ssf-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["spec_version"] == "1_0"
    assert body["configuration_endpoint"].endswith("/ssf/streams")
    assert "urn:ietf:rfc:8935" in body["delivery_methods_supported"]


def test_jwks_endpoint_serves_a_real_signing_key(client: httpx.Client):
    resp = client.get("/jwks.json")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert len(keys) >= 1
    assert keys[0]["kty"] == "RSA"
    assert keys[0]["alg"] == "RS256"
    assert "n" in keys[0] and "e" in keys[0]


def test_unknown_path_returns_404(client: httpx.Client):
    resp = client.get("/this-route-does-not-exist")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Management API — auth boundary
# ---------------------------------------------------------------------------


def test_streams_get_requires_auth(client: httpx.Client):
    resp = client.get("/ssf/streams")
    assert resp.status_code == 401


def test_streams_get_rejects_wrong_token(client: httpx.Client):
    """401 (missing/malformed header) vs 403 (present but wrong token) is a
    deliberate distinction — see app/auth.py's require_management_auth."""
    resp = client.get("/ssf/streams", headers={"Authorization": "Bearer not-the-right-token"})
    assert resp.status_code == 403


def test_streams_post_requires_auth(client: httpx.Client):
    resp = client.post("/ssf/streams", json={"aud": "x", "delivery": {"endpoint_url": "https://example.test/"}})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Management API — streams CRUD, negative paths
# ---------------------------------------------------------------------------


def test_get_streams_404_when_none_configured(client: httpx.Client):
    resp = client.get("/ssf/streams", headers=MGMT_HEADERS)
    assert resp.status_code == 404


def test_delete_stream_is_idempotent_when_none_exists(client: httpx.Client):
    resp = client.delete("/ssf/streams", headers=MGMT_HEADERS)
    assert resp.status_code == 204


def test_create_stream_missing_required_field_returns_422(client: httpx.Client):
    resp = client.post("/ssf/streams", json={"aud": "test-aud"}, headers=MGMT_HEADERS)  # no delivery block
    assert resp.status_code == 422


def test_create_stream_rejects_ssrf_endpoint_url(client: httpx.Client):
    """The real container's own DNS resolution must reject a link-local/metadata target."""
    resp = client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://169.254.169.254/latest/meta-data",
                "endpoint_url_token": "receiver-token",
            },
        },
        headers=MGMT_HEADERS,
    )
    assert resp.status_code == 400
    assert "endpoint_url" in resp.json()["detail"].lower()


def test_create_stream_rejects_non_https_endpoint_url(client: httpx.Client):
    resp = client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "http://receiver.example.test/events",
                "endpoint_url_token": "receiver-token",
            },
        },
        headers=MGMT_HEADERS,
    )
    assert resp.status_code == 400


def test_create_stream_ssrf_safe_but_unreachable_receiver_returns_502(client: httpx.Client):
    """endpoint_url resolves to a real public IP (SSRF check passes) but nothing there
    accepts the verification SET push — the container must roll back and report 502,
    not silently create a stream that can never deliver."""
    resp = client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://example.com/no-such-ssf-receiver-endpoint",
                "endpoint_url_token": "receiver-token",
            },
        },
        headers=MGMT_HEADERS,
    )
    assert resp.status_code == 502
    # Rolled back — no stream should have been left behind.
    assert client.get("/ssf/streams", headers=MGMT_HEADERS).status_code == 404


def test_patch_stream_404_when_none_configured(client: httpx.Client):
    resp = client.patch("/ssf/streams", json={"status": "paused"}, headers=MGMT_HEADERS)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Authentik webhook receiver
# ---------------------------------------------------------------------------


def test_webhook_requires_auth(client: httpx.Client):
    resp = client.post("/webhook/authentik", json={"body": {"action": "authentik.core.auth.logout"}})
    assert resp.status_code == 401


def test_webhook_rejects_wrong_token(client: httpx.Client):
    resp = client.post(
        "/webhook/authentik",
        json={"body": {"action": "authentik.core.auth.logout"}},
        headers={"Authorization": "Bearer not-the-right-token"},
    )
    assert resp.status_code == 401


def test_webhook_rejects_malformed_json(client: httpx.Client):
    resp = client.post(
        "/webhook/authentik",
        content=b"{not valid json",
        headers={**WEBHOOK_HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_webhook_with_valid_auth_and_unmapped_event_is_ignored(client: httpx.Client):
    resp = client.post(
        "/webhook/authentik",
        json={"body": {"action": "authentik.core.some.unmapped.event"}},
        headers=WEBHOOK_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ignored", "reason": "unmapped_event"}


def test_webhook_logout_with_no_stream_configured_is_ignored(client: httpx.Client):
    """A mapped, well-formed event with no active stream to deliver to must not error.

    extract_email() is checked before the stream lookup regardless of event
    type, so a user block with an email is required to reach the
    no_enabled_stream branch rather than short-circuiting on missing_email.
    """
    resp = client.post(
        "/webhook/authentik",
        json={
            "body": {
                "action": "authentik.core.auth.logout",
                "pk": "e2e-test-txn",
                "user": {"email": "e2e-test-user@example.test"},
            }
        },
        headers=WEBHOOK_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ignored", "reason": "no_enabled_stream"}
