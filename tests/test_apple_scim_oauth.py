"""Tests for Apple SCIM OAuth state TTL and CSRF protection."""

from __future__ import annotations

import time
from unittest.mock import patch

from app.routes import apple_scim as scim_routes


def test_oauth_state_expires_after_ttl():
    state = "test-state-value"
    with patch.object(scim_routes, "_STATE_TTL_SECONDS", 1):
        scim_routes._pending_states.clear()
        scim_routes._add_state(state)
        assert state in scim_routes._pending_states

        future = time.monotonic() + 2
        with patch("app.routes.apple_scim.time.monotonic", return_value=future):
            assert scim_routes._consume_state(state) is False


def test_oauth_state_single_use():
    state = "single-use-state"
    scim_routes._pending_states.clear()
    scim_routes._add_state(state)
    assert scim_routes._consume_state(state) is True
    assert scim_routes._consume_state(state) is False
