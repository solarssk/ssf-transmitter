"""Tests for POST /ssf/verification (receiver-initiated verification)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app

MGMT_TOKEN = "test_management_token_min_32_chars_1234"
MGMT_HEADERS = {"Authorization": f"Bearer {MGMT_TOKEN}"}


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_post_verification_requires_management_auth(client):
    resp = client.post("/ssf/verification")
    assert resp.status_code == 401


def test_post_verification_returns_404_without_stream(client):
    with patch("app.routes.verification.get_first_stream", new_callable=AsyncMock, return_value=None):
        resp = client.post("/ssf/verification", headers=MGMT_HEADERS)
    assert resp.status_code == 404


def test_post_verification_returns_202_for_existing_stream(client):
    from app.database import Stream

    stream = Stream(
        stream_id="s1",
        aud="aud",
        endpoint_url="https://receiver.example.test/events",
        endpoint_token="tok",
        events_requested=[],
        status="enabled",
        created_at=0,
    )
    with (
        patch("app.routes.verification.get_first_stream", new_callable=AsyncMock, return_value=stream),
        patch("app.routes.verification.push_verification_set", new_callable=AsyncMock, return_value=True),
    ):
        resp = client.post("/ssf/verification", headers=MGMT_HEADERS)

    assert resp.status_code == 202


def test_post_verification_passes_state_to_push(client):
    from app.database import Stream

    stream = Stream(
        stream_id="s1",
        aud="aud",
        endpoint_url="https://receiver.example.test/events",
        endpoint_token="tok",
        events_requested=[],
        status="enabled",
        created_at=0,
    )
    mock_push = AsyncMock(return_value=True)
    with (
        patch("app.routes.verification.get_first_stream", new_callable=AsyncMock, return_value=stream),
        patch("app.routes.verification.push_verification_set", mock_push),
    ):
        resp = client.post(
            "/ssf/verification",
            headers=MGMT_HEADERS,
            json={"state": "receiver-correlation-token"},
        )

    assert resp.status_code == 202
    mock_push.assert_called_once_with(stream, state="receiver-correlation-token")


def test_post_verification_returns_502_when_push_fails(client):
    from app.database import Stream

    stream = Stream(
        stream_id="s1",
        aud="aud",
        endpoint_url="https://receiver.example.test/events",
        endpoint_token="tok",
        events_requested=[],
        status="enabled",
        created_at=0,
    )
    with (
        patch("app.routes.verification.get_first_stream", new_callable=AsyncMock, return_value=stream),
        patch("app.routes.verification.push_verification_set", new_callable=AsyncMock, return_value=False),
    ):
        resp = client.post("/ssf/verification", headers=MGMT_HEADERS)

    assert resp.status_code == 502


def test_post_verification_accepts_bare_string_as_state(client):
    """A raw JSON string body is coerced to {"state": value}."""
    from app.database import Stream

    stream = Stream(
        stream_id="s1", aud="aud",
        endpoint_url="https://receiver.example.test/events",
        endpoint_token="tok", events_requested=[], status="enabled", created_at=0,
    )
    mock_push = AsyncMock(return_value=True)
    with (
        patch("app.routes.verification.get_first_stream", new_callable=AsyncMock, return_value=stream),
        patch("app.routes.verification.push_verification_set", mock_push),
    ):
        resp = client.post(
            "/ssf/verification",
            content=b'"bare-state-token"',
            headers={**MGMT_HEADERS, "Content-Type": "application/json"},
        )

    assert resp.status_code == 202
    mock_push.assert_called_once_with(stream, state="bare-state-token")


def test_post_verification_empty_body_is_accepted(client):
    """Body is optional — omitting it should not cause a 422."""
    from app.database import Stream

    stream = Stream(
        stream_id="s1",
        aud="aud",
        endpoint_url="https://receiver.example.test/events",
        endpoint_token="tok",
        events_requested=[],
        status="enabled",
        created_at=0,
    )
    with (
        patch("app.routes.verification.get_first_stream", new_callable=AsyncMock, return_value=stream),
        patch("app.routes.verification.push_verification_set", new_callable=AsyncMock, return_value=True),
    ):
        resp = client.post("/ssf/verification", headers=MGMT_HEADERS)

    assert resp.status_code == 202
