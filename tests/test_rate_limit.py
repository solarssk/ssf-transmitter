"""Tests for app.rate_limit.shared_limit — PATCH /ssf/streams rate-limit sharing.

Regression test for a real bug: PATCH /ssf/streams and PATCH /ssf/streams/{id}
each had their own @limiter.limit("20/minute") decorator. slowapi's default
key_style ("url") folds the request's literal path into each route's own
rate-limit bucket, so the two routes — which both mutate the same single
stream — got independent counters: an operator could double the effective
limit by alternating between the two paths.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

MGMT_HEADERS = {"Authorization": "Bearer test_management_token_min_32_chars_1234"}


@pytest.fixture
def client():
    with TestClient(app) as tc:
        yield tc


def _create_stream(client: TestClient) -> str:
    resp = client.post(
        "/ssf/streams",
        json={
            "aud": "test-aud",
            "delivery": {
                "endpoint_url": "https://receiver.example.test/events",
                "endpoint_url_token": "receiver-token",
            },
        },
        headers=MGMT_HEADERS,
    )
    assert resp.status_code == 201
    return resp.json()["stream_id"]


@pytest.mark.enable_rate_limit
def test_patch_stream_rate_limit_is_shared_across_both_routes(client: TestClient):
    from app.rate_limit import limiter

    limiter.reset()
    stream_id = _create_stream(client)

    statuses = []
    for i in range(20):
        # Alternate between the two PATCH routes for the same stream.
        if i % 2 == 0:
            resp = client.patch("/ssf/streams", json={"status": "enabled"}, headers=MGMT_HEADERS)
        else:
            resp = client.patch(f"/ssf/streams/{stream_id}", json={"status": "enabled"}, headers=MGMT_HEADERS)
        statuses.append(resp.status_code)

    assert all(s == 200 for s in statuses), statuses

    # The 21st request, on EITHER route, must now be rate-limited — proving
    # the two routes share one counter rather than each getting its own 20.
    resp_a = client.patch("/ssf/streams", json={"status": "enabled"}, headers=MGMT_HEADERS)
    assert resp_a.status_code == 429

    resp_b = client.patch(f"/ssf/streams/{stream_id}", json={"status": "enabled"}, headers=MGMT_HEADERS)
    assert resp_b.status_code == 429
