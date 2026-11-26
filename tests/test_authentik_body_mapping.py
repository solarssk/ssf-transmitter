"""Verify the deployable Authentik expression uses target identity and safe context."""

import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from app.events.mapper import CREDENTIAL_CHANGE, SESSION_REVOKED, map_authentik_event


def render(monkeypatch, action, context, target=None):
    module = types.ModuleType("authentik.core.models")
    module.User = SimpleNamespace(
        objects=SimpleNamespace(filter=Mock(return_value=SimpleNamespace(first=lambda: target)))
    )
    monkeypatch.setitem(sys.modules, "authentik.core.models", module)
    expression = Path("integrations/authentik/webhook-body.py.txt").read_text()
    namespace = {}
    # Execute only the committed mapping template, never webhook content.
    exec("def expression(notification):\n" + "\n".join("    " + line for line in expression.splitlines()), namespace)  # noqa: S102
    event = SimpleNamespace(action=action, context=context, user={"email": "admin@example.com"}, pk="event-id")
    return namespace["expression"](SimpleNamespace(event=event))


def test_admin_disable_targets_account_not_administrator(monkeypatch):
    body = render(
        monkeypatch,
        "model_updated",
        {"model": {"app": "authentik_core", "model_name": "user", "pk": 148}},
        SimpleNamespace(is_active=False, email="target@example.com", username="target"),
    )
    assert body["body"]["user"]["email"] == "target@example.com"
    assert [e.uri for e in map_authentik_event(body)] == [SESSION_REVOKED]


def test_local_logout_is_ignored(monkeypatch):
    assert map_authentik_event(render(monkeypatch, "logout", {})) == []


def test_active_missing_or_wrong_model_never_revokes(monkeypatch):
    for model, target in [
        ({"app": "authentik_core", "model_name": "user", "pk": 1}, None),
        ({"app": "authentik_core", "model_name": "user", "pk": 1}, SimpleNamespace(is_active=True)),
        ({"app": "other", "model_name": "user"}, None),
    ]:
        assert map_authentik_event(render(monkeypatch, "model_updated", {"model": model}, target)) == []


def test_password_context_is_normalized_without_secrets(monkeypatch):
    body = render(monkeypatch, "user_write", {"created": False, "password": "secret-value"})
    assert "secret-value" not in str(body)
    assert [e.uri for e in map_authentik_event(body)] == [CREDENTIAL_CHANGE]


def test_created_user_does_not_emit_password_change(monkeypatch):
    assert map_authentik_event(render(monkeypatch, "user_write", {"created": True, "password": "x"})) == []
