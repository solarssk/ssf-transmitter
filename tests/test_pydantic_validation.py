"""Tests for strict Pydantic validation on SSF stream management endpoints.

All 422 responses are from FastAPI/Pydantic rejecting the request body before
it reaches the handler.  400 responses are from application-level validation
(URL validation, DB layer).
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}

VALID_PAYLOAD = {
    "aud": "apple-business-manager",
    "delivery": {
        "endpoint_url": "https://receiver.example.test/events",
        "endpoint_url_token": "receiver-secret-token",
    },
    "events_requested": [
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    ],
}


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# aud validation
# ---------------------------------------------------------------------------


def test_empty_aud_rejected(client: TestClient):
    payload = {**VALID_PAYLOAD, "aud": ""}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422
    assert "aud" in resp.text.lower()


def test_multi_value_aud_list_rejected(client: TestClient):
    payload = {**VALID_PAYLOAD, "aud": ["aud-one", "aud-two"]}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


def test_single_element_aud_list_normalised(client: TestClient):
    """A single-element list is normalised to a plain string."""
    payload = {**VALID_PAYLOAD, "aud": ["apple-business-manager"]}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 201
    assert resp.json()["aud"] == "apple-business-manager"


def test_missing_aud_rejected(client: TestClient):
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "aud"}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# events_requested validation
# ---------------------------------------------------------------------------


def test_unsupported_event_uri_rejected(client: TestClient):
    payload = {**VALID_PAYLOAD, "events_requested": ["https://evil.example.com/custom-event"]}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422
    assert "unsupported" in resp.text.lower()


def test_all_supported_event_uris_accepted(client: TestClient):
    submitted = [
        "https://schemas.openid.net/secevent/ssf/event-type/verification",
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    ]
    payload = {**VALID_PAYLOAD, "events_requested": submitted}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 201
    assert resp.json()["events_requested"] == submitted


def test_empty_events_requested_accepted(client: TestClient):
    payload = {**VALID_PAYLOAD, "events_requested": []}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 201


def test_events_requested_absent_defaults_to_empty(client: TestClient):
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "events_requested"}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 201
    assert resp.json()["events_requested"] == []


# ---------------------------------------------------------------------------
# delivery validation
# ---------------------------------------------------------------------------


def test_missing_delivery_rejected(client: TestClient):
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "delivery"}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


def test_missing_endpoint_url_rejected(client: TestClient):
    payload = {**VALID_PAYLOAD, "delivery": {"endpoint_url_token": "tok"}}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


def test_unsupported_delivery_method_rejected(client: TestClient):
    payload = {
        **VALID_PAYLOAD,
        "delivery": {
            **VALID_PAYLOAD["delivery"],
            "method": "https://example.com/custom-delivery",
        },
    }
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


def test_supported_delivery_method_rfc8935_accepted(client: TestClient):
    payload = {
        **VALID_PAYLOAD,
        "delivery": {
            **VALID_PAYLOAD["delivery"],
            "method": "urn:ietf:rfc:8935",
        },
    }
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 201


def test_extra_fields_in_delivery_rejected(client: TestClient):
    payload = {
        **VALID_PAYLOAD,
        "delivery": {
            **VALID_PAYLOAD["delivery"],
            "unknown_field": "injected",
        },
    }
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Top-level extra fields
# ---------------------------------------------------------------------------


def test_extra_top_level_field_rejected(client: TestClient):
    payload = {**VALID_PAYLOAD, "injected_field": "value"}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# status validation
# ---------------------------------------------------------------------------


def test_invalid_status_on_create_rejected(client: TestClient):
    payload = {**VALID_PAYLOAD, "status": "invalid_status"}
    resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
    assert resp.status_code == 422


def test_valid_statuses_on_create_accepted(client: TestClient):
    for status in ("enabled", "paused", "disabled"):
        payload = {**VALID_PAYLOAD, "status": status}
        resp = client.post("/ssf/streams", json=payload, headers=MGMT_HEADERS)
        assert resp.status_code == 201, f"status={status!r} should be accepted"
        assert resp.json()["status"] == status


# ---------------------------------------------------------------------------
# PATCH validation
# ---------------------------------------------------------------------------


def test_patch_invalid_status_rejected(client: TestClient):
    # Ensure a stream exists first
    client.post("/ssf/streams", json=VALID_PAYLOAD, headers=MGMT_HEADERS)
    resp = client.patch("/ssf/streams", json={"status": "bad_value"}, headers=MGMT_HEADERS)
    assert resp.status_code == 422


def test_patch_extra_field_rejected(client: TestClient):
    client.post("/ssf/streams", json=VALID_PAYLOAD, headers=MGMT_HEADERS)
    resp = client.patch("/ssf/streams", json={"status": "paused", "evil": "field"}, headers=MGMT_HEADERS)
    assert resp.status_code == 422


def test_patch_unsupported_event_uri_rejected(client: TestClient):
    client.post("/ssf/streams", json=VALID_PAYLOAD, headers=MGMT_HEADERS)
    resp = client.patch(
        "/ssf/streams",
        json={"events_requested": ["https://attacker.example/evil"]},
        headers=MGMT_HEADERS,
    )
    assert resp.status_code == 422


def test_patch_multi_value_aud_rejected(client: TestClient):
    client.post("/ssf/streams", json=VALID_PAYLOAD, headers=MGMT_HEADERS)
    resp = client.patch("/ssf/streams", json={"aud": ["a", "b"]}, headers=MGMT_HEADERS)
    assert resp.status_code == 422
