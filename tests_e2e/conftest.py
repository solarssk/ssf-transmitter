"""Fixtures for the container E2E suite.

Unlike tests/ (in-process, TestClient, fully hermetic), these hit a *real*
running instance of the Docker image over real HTTP — the same image CI
builds and Trivy-scans, started the same way the smoke-test step already
does. This is a separate top-level directory (not under tests/, and not
picked up by pyproject.toml's `testpaths = ["tests"]`) precisely so it
never runs as part of the fast, hermetic default `pytest` invocation:
it needs a container already up and listening, which the rest of the
suite has no business assuming.

Run against a container started the same way ci.yml's smoke-test step
starts one, e.g.:

    docker run -d --rm -p 18000:8000 \
      -e SSF_CONTAINER_PORT=8000 \
      -e SSF_ISSUER=https://ssf.ci.invalid \
      -e SSF_BASE_URL=https://ssf.ci.invalid \
      -e SSF_WEBHOOK_TOKEN=ci-smoke-test-webhook-token-000000 \
      -e SSF_MANAGEMENT_TOKEN=ci-smoke-test-mgmt-token-0000000 \
      ssf-transmitter:ci
    E2E_BASE_URL=http://localhost:18000 pytest tests_e2e/

E2E_BASE_URL / E2E_MANAGEMENT_TOKEN / E2E_WEBHOOK_TOKEN env vars override
the defaults below, which already match ci.yml's smoke-test container.
"""

from __future__ import annotations

import os

import httpx
import pytest

BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:18000")
MANAGEMENT_TOKEN = os.environ.get("E2E_MANAGEMENT_TOKEN", "ci-smoke-test-mgmt-token-0000000")
WEBHOOK_TOKEN = os.environ.get("E2E_WEBHOOK_TOKEN", "ci-smoke-test-webhook-token-000000")

MGMT_HEADERS = {"Authorization": f"Bearer {MANAGEMENT_TOKEN}"}
WEBHOOK_HEADERS = {"Authorization": f"Bearer {WEBHOOK_TOKEN}"}


@pytest.fixture(scope="session")
def client():
    # 30s, not 10s: app/events/pusher.py's own outbound push has a 10s
    # timeout, and test_create_stream_ssrf_safe_but_unreachable_receiver_returns_502
    # relies on that server-side timeout actually firing and the route
    # rolling back and responding with 502 — a client timeout equal to the
    # server's races it (and generally loses), raising httpx.ReadTimeout in
    # the test instead of ever seeing the 502. Give real margin beyond it.
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as c:
        yield c


@pytest.fixture(autouse=True)
def _no_stream_configured(client: httpx.Client):
    """Ensure a clean slate before and after every test.

    The transmitter models a single active stream — DELETE is unconditional
    and idempotent (204 whether or not one exists), so this is cheap and
    doesn't depend on prior test ordering or leftover state from a previous
    run against the same container.
    """
    client.delete("/ssf/streams", headers=MGMT_HEADERS)
    yield
    client.delete("/ssf/streams", headers=MGMT_HEADERS)
