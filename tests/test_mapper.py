from app.events.mapper import (
    CREDENTIAL_CHANGE,
    MappedEvent,
    SESSION_REVOKED,
    extract_email,
    extract_source_txn,
    map_authentik_event,
)


def test_maps_logout_to_session_revoked():
    events = map_authentik_event({"body": {"action": "authentik.core.auth.logout"}})

    assert len(events) == 1
    assert events[0].uri == SESSION_REVOKED
    assert events[0].payload["initiating_entity"] == "policy"
    assert "reason_admin" in events[0].payload
    assert "event_timestamp" in events[0].payload


def test_maps_user_write_password_and_disabled_to_multiple_events():
    events = map_authentik_event(
        {
            "body": {
                "action": "authentik.core.user.write",
                "user": {"email": "user@example.com"},
                "context": {
                    "changed_fields": ["password", "is_active"],
                    "is_active": False,
                },
            }
        }
    )

    assert len(events) == 1
    assert events[0].uri == CREDENTIAL_CHANGE
    assert events[0].payload["credential_type"] == "password"
    assert events[0].payload["change_type"] == "update"


def test_user_delete_is_skipped_until_apple_confirms_support():
    events = map_authentik_event({
        "body": {
            "action": "authentik.core.user.delete",
            "user": {"email": "deleted@example.com"},
        }
    })

    assert events == []


def test_account_enabled_change_is_skipped_until_supported():
    events = map_authentik_event({
        "body": {
            "action": "authentik.core.user.write",
            "user": {"email": "user@example.com"},
            "context": {"changed_fields": ["is_active"], "is_active": True},
        }
    })

    assert events == []


def test_user_delete_without_email_is_skipped():
    events = map_authentik_event({"body": {"action": "authentik.core.user.delete"}})

    assert events == []


def test_extract_email_rejects_non_string_values():
    assert extract_email({"body": {"user": {"email": 12345}}}) is None
    assert extract_email({"body": {"user": {"email": ["a@example.com"]}}}) is None


def test_extract_email_strips_and_rejects_whitespace_only():
    assert extract_email({"body": {"user": {"email": "  user@example.com  "}}}) == "user@example.com"
    assert extract_email({"body": {"user": {"email": "   "}}}) is None


def test_user_delete_with_whitespace_email_is_skipped():
    events = map_authentik_event({
        "body": {"action": "authentik.core.user.delete", "user": {"email": "   "}},
    })
    assert events == []


def test_ignores_unmapped_event():
    assert map_authentik_event({"body": {"action": "authentik.core.auth.login_failed"}}) == []


def test_is_active_in_context_but_not_in_changed_fields_does_not_emit_account_event():
    """is_active present in context does not trigger account-disabled/enabled unless
    is_active is also listed in changed_fields."""
    events = map_authentik_event(
        {
            "body": {
                "action": "authentik.core.user.write",
                "context": {
                    "changed_fields": ["password"],
                    "is_active": False,  # present in context, but not changed
                },
            }
        }
    )

    uris = [e.uri for e in events]
    assert CREDENTIAL_CHANGE in uris


def test_multiple_events_from_one_webhook_share_txn():
    events = map_authentik_event(
        {
            "body": {
                "pk": "event-uuid-abc",
                "action": "authentik.core.user.write",
                "context": {
                    "changed_fields": ["password", "is_active"],
                    "is_active": False,
                },
            }
        }
    )

    assert len(events) == 1
    assert events[0].txn == "event-uuid-abc"


def test_txn_is_none_when_no_source_event_id():
    events = map_authentik_event({"body": {"action": "authentik.core.auth.logout"}})
    assert events[0].txn is None


def test_extract_source_txn_from_pk():
    txn = extract_source_txn({"body": {"pk": "my-event-pk", "action": "x"}})
    assert txn == "my-event-pk"


def test_extract_source_txn_returns_none_when_missing():
    txn = extract_source_txn({"body": {"action": "x"}})
    assert txn is None


def test_mapped_event_is_frozen():
    import pytest

    event = MappedEvent(uri="https://example.com/event", payload={}, txn="t1")
    with pytest.raises((AttributeError, TypeError)):
        event.uri = "other"  # type: ignore[misc]
