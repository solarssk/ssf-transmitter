from app.events.mapper import (
    ACCOUNT_DISABLED,
    ACCOUNT_ENABLED,
    ACCOUNT_PURGED,
    CREDENTIAL_CHANGE,
    SESSION_REVOKED,
    MappedEvent,
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
                "context": {
                    "changed_fields": ["password", "is_active"],
                    "is_active": False,
                },
            }
        }
    )

    assert len(events) == 2
    assert events[0].uri == CREDENTIAL_CHANGE
    assert events[0].payload["credential_type"] == "password"
    assert events[0].payload["change_type"] == "update"
    assert events[1].uri == ACCOUNT_DISABLED
    assert events[1].payload == {}


def test_maps_user_delete_to_account_purged():
    events = map_authentik_event({"body": {"action": "authentik.core.user.delete"}})

    assert len(events) == 1
    assert events[0].uri == ACCOUNT_PURGED
    assert events[0].payload == {}


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
    assert ACCOUNT_DISABLED not in uris
    assert ACCOUNT_ENABLED not in uris


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

    assert len(events) == 2
    assert events[0].txn == "event-uuid-abc"
    assert events[1].txn == "event-uuid-abc"


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
